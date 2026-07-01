from __future__ import annotations

import asyncio
import logging
import math
import time
from collections import defaultdict
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)

# ── Rate tracker ────────────────────────────────────────────────
_packet_times: dict[str, list[float]] = defaultdict(list)
_byte_counts: dict[str, int] = defaultdict(int)


def _rate_features(src_ip: str, packet_len: int, now: float) -> np.ndarray:
    window = 5.0
    ts_list = _packet_times[src_ip]
    ts_list.append(now)
    cutoff = now - window
    while ts_list and ts_list[0] < cutoff:
        ts_list.pop(0)
    count = len(ts_list)
    _byte_counts[src_ip] += packet_len
    rate = count / window if window > 0 else 0
    bps = _byte_counts[src_ip] / window
    return np.array([
        min(rate / 1000.0, 1.0),
        min(bps / 1_000_000.0, 1.0),
        min(count / 100.0, 1.0),
    ], dtype=np.float32)


def reset_rates() -> None:
    _packet_times.clear()
    _byte_counts.clear()


_SQL_PATTERNS = [
    b"SELECT", b"UNION", b"DROP ", b"DELETE", b"INSERT",
    b"OR 1=1", b"' OR", b'" OR', b"1=1", b"--",
]
_SHELL_PATTERNS = [
    b";", b"|", b"&", b"`", b"$(", b">", b"whoami", b"cat ", b"/etc/",
]
_PATH_TRAVERSAL = [b"../", b"..\\"]
_XSS_PATTERNS = [b"<script", b"onerror", b"onload", b"alert("]


def extract_packet_features(packet) -> tuple[np.ndarray, str]:
    f = np.zeros(48, dtype=np.float32)
    payload_text = ""

    # ── Layer 3 (IP) features 0-9 ──────────────────────────────
    ip = None
    if packet.haslayer("IP"):
        ip = packet["IP"]
    elif packet.haslayer("IPv6"):
        ip = packet["IPv6"]

    if ip is None:
        return f, payload_text

    src_ip = ip.src
    dst_ip = ip.dst
    proto = ip.proto
    ttl = ip.ttl
    pkt_len = ip.len

    f[0] = 1.0 if proto == 6 else 0.0  # TCP
    f[1] = 1.0 if proto == 17 else 0.0  # UDP
    f[2] = 1.0 if proto == 1 else 0.0   # ICMP
    f[3] = min(pkt_len / 1500.0, 1.0)   # normalized packet length
    f[4] = min(ttl / 255.0, 1.0)         # TTL
    f[5] = 1.0 if _is_private_ip(src_ip) else 0.0
    f[6] = 1.0 if _is_private_ip(dst_ip) else 0.0

    # ── Layer 4 (TCP/UDP) features 10-19 ──────────────────────
    src_port = 0
    dst_port = 0
    flags = 0
    window = 0

    tcp = packet.getlayer("TCP")
    udp = packet.getlayer("UDP")

    if tcp is not None:
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags
        window = tcp.window

        f[7] = 1.0 if (flags & 0x02) else 0.0  # SYN
        f[8] = 1.0 if (flags & 0x10) else 0.0  # ACK
        f[9] = 1.0 if (flags & 0x01) else 0.0  # FIN
        f[10] = 1.0 if (flags & 0x04) else 0.0  # RST
        f[11] = 1.0 if (flags & 0x08) else 0.0  # PSH
        f[12] = 1.0 if (flags & 0x20) else 0.0  # URG
        f[13] = min(window / 65535.0, 1.0)
        f[14] = 1.0 if dst_port == 80 or dst_port == 8080 else 0.0
        f[15] = 1.0 if dst_port == 443 else 0.0
        f[16] = 1.0 if dst_port == 22 else 0.0
        f[17] = 1.0 if dst_port < 1024 else 0.0  # well-known
        f[18] = 1.0 if _is_ephemeral(src_port) else 0.0

    elif udp is not None:
        src_port = udp.sport
        dst_port = udp.dport
        f[7] = 0.0
        f[8] = 0.0
        f[9] = 0.0
        f[10] = 0.0
        f[11] = 0.0
        f[12] = 0.0
        f[13] = 0.0
        f[14] = 1.0 if dst_port == 53 else 0.0  # DNS
        f[15] = 1.0 if dst_port == 123 else 0.0  # NTP
        f[16] = 1.0 if dst_port == 443 else 0.0  # QUIC
        f[17] = 1.0 if dst_port < 1024 else 0.0
        f[18] = 1.0 if _is_ephemeral(src_port) else 0.0

    # ── Payload analysis features 19-34 ─────────────────────────
    raw_bytes = bytes(packet.getlayer("Raw")) if packet.haslayer("Raw") else b""
    payload_text = raw_bytes.decode("utf-8", errors="replace")

    payload_len = len(raw_bytes)
    f[19] = min(payload_len / 1460.0, 1.0)

    if payload_len > 0:
        printable = sum(1 for b in raw_bytes if 32 <= b <= 126)
        f[20] = printable / payload_len

        uppercase = sum(1 for b in raw_bytes if 65 <= b <= 90)
        f[21] = uppercase / payload_len

        digit = sum(1 for b in raw_bytes if 48 <= b <= 57)
        f[22] = digit / payload_len

        space = raw_bytes.count(b" ")
        f[23] = min(space / 100.0, 1.0)

        special = sum(1 for b in raw_bytes if b in b"!@#$%^&*()_+-=[]{}|;':\",./<>?`~")
        f[24] = min(special / 50.0, 1.0)

        f[25] = min(_entropy(raw_bytes) / 8.0, 1.0)

    upper_text = payload_text.upper()

    sqli_count = sum(1 for p in _SQL_PATTERNS if p.upper() in upper_text.encode())
    f[26] = min(sqli_count / 5.0, 1.0)
    f[27] = 1.0 if "'" in payload_text else 0.0
    f[28] = 1.0 if "--" in payload_text or "/*" in payload_text else 0.0
    f[29] = 1.0 if "OR " in upper_text and "=" in payload_text else 0.0

    shell_count = sum(1 for p in _SHELL_PATTERNS if p in raw_bytes)
    f[30] = min(shell_count / 5.0, 1.0)
    f[31] = 1.0 if b"whoami" in raw_bytes or b"id" in raw_bytes else 0.0
    f[32] = 1.0 if b"cat " in raw_bytes or b"/etc/" in raw_bytes else 0.0
    f[33] = 1.0 if b"curl" in raw_bytes or b"wget" in raw_bytes else 0.0

    pt_count = sum(1 for p in _PATH_TRAVERSAL if p in raw_bytes)
    f[34] = min(pt_count / 3.0, 1.0)

    xss_count = sum(1 for p in _XSS_PATTERNS if p in raw_bytes)
    f[35] = min(xss_count / 3.0, 1.0)
    f[36] = 1.0 if b"javascript:" in raw_bytes or b"onerror" in raw_bytes else 0.0

    enc_count = raw_bytes.count(b"%") // 3
    f[37] = min(enc_count / 10.0, 1.0)

    null_count = raw_bytes.count(b"\x00")
    f[38] = min(null_count / 10.0, 1.0)

    # ── Rate features 39-47 ────────────────────────────────────
    now = time.time()
    rate_feats = _rate_features(src_ip, pkt_len, now)
    f[39:42] = rate_feats

    f[42] = 1.0 if flags == 0x02 and dst_port in (80, 443, 8080) else 0.0  # SYN scan
    f[43] = 1.0 if flags == 0x29 else 0.0  # Xmas scan (FIN+PSH+URG)
    f[44] = 1.0 if flags == 0x00 else 0.0  # NULL scan
    f[45] = 1.0 if dst_port == 0 else 0.0
    f[46] = min(len(raw_bytes) / 4096.0, 1.0)

    sport_class = src_port // 1024
    f[47] = min(sport_class / 64.0, 1.0)

    return f, payload_text


def _is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    if ip.startswith("192.168."):
        return True
    return False


def _is_ephemeral(port: int) -> bool:
    return 49152 <= port <= 65535


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


# ── Live capture feeder ─────────────────────────────────────────
class PacketCaptureFeeder:
    def __init__(
        self,
        interface: str,
        pipeline,
        bpf_filter: str = "tcp or udp",
    ) -> None:
        self.interface = interface
        self.pipeline = pipeline
        self.bpf_filter = bpf_filter
        self._task: Optional[asyncio.Task] = None
        self._sniffer: Optional[object] = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._capture_loop())

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            try:
                self._sniffer.stop()
            except PermissionError:
                log.warning(
                    "Packet capture requires root. Try: sudo .venv/bin/python -m lympa --capture %s",
                    self.interface,
                )
            except Exception:
                pass
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _capture_loop(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            log.error(
                "scapy not installed. Install with: pip install scapy"
            )
            return

        log.info(
            "Starting packet capture on %s (filter: %s)",
            self.interface, self.bpf_filter,
        )

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=lambda pkt: asyncio.create_task(self._on_packet(pkt)),
            store=False,
        )
        self._sniffer = sniffer
        try:
            sniffer.start()
        except PermissionError:
            log.error(
                "Permission denied. Packet capture requires root. "
                "Try: sudo .venv/bin/python -m lympa --capture %s",
                self.interface,
            )
            return
        except Exception as exc:
            log.error("Failed to start capture: %s", exc)
            return

        log.info("Packet capture started on %s", self.interface)

        try:
            while self._running:
                await asyncio.sleep(1)
        finally:
            pass

    async def _on_packet(self, packet) -> None:
        try:
            features, payload_text = extract_packet_features(packet)

            src_ip = "0.0.0.0"
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
            elif packet.haslayer("IPv6"):
                src_ip = packet["IPv6"].src

            if np.all(features == 0):
                return

            results = await self.pipeline.ingest_features(features, src_ip)

            if payload_text and results and results[0].verdict.name == "WARNING":
                await self.pipeline.ingest_logs([payload_text], src_ip)

        except Exception as exc:
            log.debug("Packet processing error: %s", exc)
