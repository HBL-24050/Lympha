import json
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import (
    DB_PATH,
    EVE_PATH,
    INTERFACE,
    MODE,
    SECUREBERT_THRESHOLD,
    SURICATA_THRESHOLD,
    WINDOW_MINUTES,
)
from core.database import Database
from core.firewall import Firewall
from models.securebert_worker import PayloadResult, SecureBERTWorker


class SlidingWindowTracker:
    def __init__(self, window_minutes: int = 2, threshold: int = 3):
        self.window = timedelta(minutes=window_minutes)
        self.threshold = threshold
        self._events: dict[str, list[datetime]] = defaultdict(list)
        self._lock = threading.Lock()

    def add_event(self, ip: str) -> bool:
        now = datetime.now()
        cutoff = now - self.window
        with self._lock:
            self._events[ip] = [t for t in self._events[ip] if t > cutoff]
            self._events[ip].append(now)
            return len(self._events[ip]) >= self.threshold

    def clear(self, ip: str):
        with self._lock:
            self._events.pop(ip, None)


class Orchestrator:
    def __init__(
        self,
        interface: str = INTERFACE,
        eve_path: str = EVE_PATH,
        suricata_threshold: int = SURICATA_THRESHOLD,
        securebert_threshold: int = SECUREBERT_THRESHOLD,
        window_minutes: int = WINDOW_MINUTES,
        db_path: str = DB_PATH,
        mode: str = MODE,
    ):
        self.interface = interface
        self.eve_path = eve_path
        self.mode = mode
        self.test_mode = mode == "test"
        self.suricata_tracker = SlidingWindowTracker(window_minutes, suricata_threshold)
        self.securebert_tracker = SlidingWindowTracker(window_minutes, securebert_threshold)
        self.db = Database(db_path)
        self.fw = Firewall()
        self.securebert = SecureBERTWorker()
        self.running = False
        self.blocked_ips: Set[str] = set()

    def _on_suricata_alert(self, alert: dict):
        src_ip = alert.get("src_ip")
        if not src_ip:
            return

        already_blocked = src_ip in self.blocked_ips
        if already_blocked and not self.test_mode:
            return

        sig = alert.get("alert", {}).get("signature", "unknown")
        severity = alert.get("alert", {}).get("severity", 3)
        tag = " [BLOCKED]" if already_blocked else ""
        print(f"[Suricata] src={src_ip} sig={sig!r} severity={severity}{tag}")

        self.db.insert_event(
            source_ip=src_ip,
            event_type="suricata",
            description=sig,
            severity=severity,
            raw_data=json.dumps(alert),
        )

        if severity <= 1:
            self._block(src_ip, f"Suricata critical: {sig}")
            return

        if self.suricata_tracker.add_event(src_ip):
            self._block(src_ip, f"Suricata threshold exceeded ({sig})")

    def _on_securebert_alert(self, result: PayloadResult):
        ip = result.source_ip
        already_blocked = ip in self.blocked_ips
        if already_blocked and not self.test_mode:
            return

        tag = " [BLOCKED]" if already_blocked else ""
        print(
            f"[SecureBERT] src={ip} score={result.anomaly_score:.3f} "
            f"{result.method} {result.path}{tag}"
        )

        self.db.insert_event(
            source_ip=ip,
            event_type="securebert",
            description=f"Anomaly {result.anomaly_score:.3f} on {result.method} {result.path}",
            severity=int(result.anomaly_score * 10),
            raw_data=json.dumps(result.__dict__, default=str),
        )

        if self.securebert_tracker.add_event(ip):
            self._block(ip, "SecureBERT anomaly threshold exceeded")

    def unblock_ip(self, ip: str):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        self.db.remove_block(ip)
        self.fw.unblock_ip(ip)
        print(f"Unblocked {ip}")

    def _block(self, ip: str, reason: str):
        if ip in self.blocked_ips:
            return
        self.blocked_ips.add(ip)
        self.db.insert_block(ip, reason)
        if self.test_mode:
            print(f"  [TEST MODE] would block {ip}: {reason}")
        else:
            self.fw.block_ip(ip)

    def _tail_eve(self):
        path = Path(self.eve_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = ""

        while self.running:
            try:
                if not path.exists():
                    time.sleep(1)
                    continue
                with open(path, "r") as fh:
                    fh.seek(0, 2)
                    while self.running:
                        chunk = fh.read()
                        if chunk:
                            partial += chunk
                            lines = partial.split("\n")
                            partial = lines.pop(-1)
                            for line in lines:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    ev = json.loads(line)
                                    if ev.get("event_type") == "alert":
                                        self._on_suricata_alert(ev)
                                except json.JSONDecodeError:
                                    pass
                        else:
                            time.sleep(0.1)
            except Exception as exc:
                print(f"[eve tail] {exc}")
                time.sleep(2)

    def _run_securebert(self):
        print(f"[SecureBERT] Starting sniffer on {self.interface}")
        try:
            self.securebert.start_sniffing(
                callback=self._on_securebert_alert,
                interface=self.interface,
            )
        except Exception as exc:
            print(f"[SecureBERT] {exc}")

    def _write_suricata_config(self):
        from core.config import HTTP_PORTS

        template_path = Path("suricata/config/suricata.yaml.template")
        config_path = Path("suricata/config/suricata.yaml")
        template = template_path.read_text() if template_path.exists() else ""
        if not template:
            return
        updated = (
            template.replace("__INTERFACE__", self.interface)
            .replace("__HTTP_PORTS__", HTTP_PORTS)
        )
        if config_path.exists() and config_path.read_text() == updated:
            print(f"  suricata config OK: interface={self.interface} ports={HTTP_PORTS}")
        else:
            config_path.write_text(updated)
            print(f"  suricata config updated: interface={self.interface} ports={HTTP_PORTS}")

        self._restart_suricata()

    def _restart_suricata(self):
        import subprocess

        try:
            r = subprocess.run(
                ["docker", "compose", "up", "-d", "--force-recreate", "suricata"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                print("  suricata container ready")
            else:
                print(f"  suricata error: {r.stderr.strip()}")
        except FileNotFoundError:
            print("  Docker not found — cannot restart Suricata")
        except subprocess.TimeoutExpired:
            print("  docker compose timed out")

    def _check_suricata(self):
        import subprocess

        try:
            r = subprocess.run(
                ["docker", "ps", "--filter", "name=suricata", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                return f"container {r.stdout.strip().split()[0]}"
            return "not running (try: docker compose up -d)"
        except FileNotFoundError:
            return "Docker not found"

    def run(self):
        if not self.interface:
            raise SystemExit(
                "LYMPHA_INTERFACE is not set. "
                "Add LYMPHA_INTERFACE=wlan0 (or your interface) to lympha.conf.\n"
                f"  Looking for lympha.conf at: {Path(__file__).resolve().parent.parent / 'lympha.conf'}\n"
                f"  Current CWD: {Path.cwd()}\n"
                f"  Try: python3 main.py --interface wlan0"
            )
        self.running = True
        self.db.initialize()
        self._write_suricata_config()

        suricata_status = self._check_suricata()
        securebert_status = (
            "model loaded" if self.securebert.model is not None
            else "heuristic fallback (model unavailable)"
        )

        width = 56
        print("╭" + "─" * width + "╮")
        print(f"│ {'Lympha — AI Network Security':^{width}} │")
        print("├" + "─" * width + "┤")
        print(f"│ Mode         │ {self.mode:<{width - 14}} │")
        print(f"│ Suricata     │ {suricata_status:<{width - 14}} │")
        print(f"│ SecureBERT   │ {securebert_status:<{width - 14}} │")
        print(f"│ Interface    │ {self.interface:<{width - 14}} │")
        print(f"│ Events       │ {self.eve_path:<{width - 14}} │")
        print("╰" + "─" * width + "╯")

        eve_ready = Path(self.eve_path).parent.exists()
        print(f"\n  eve.json target: {'OK' if eve_ready else 'waiting'} ({self.eve_path})")
        print()

        threads = [
            threading.Thread(target=self._tail_eve, daemon=True),
            threading.Thread(target=self._run_securebert, daemon=True),
        ]

        for t in threads:
            t.start()

        print(f"Orchestrator running — monitoring {self.interface}")

        def shutdown(*_):
            print("\nShutting down ...")
            self.running = False

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        while self.running:
            time.sleep(1)

        for t in threads:
            t.join(timeout=3)
        print("Orchestrator stopped.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Lympha network security orchestrator")
    parser.add_argument("--interface", default=INTERFACE)
    parser.add_argument("--eve-path", default=EVE_PATH)
    parser.add_argument("--suricata-threshold", type=int, default=SURICATA_THRESHOLD)
    parser.add_argument("--securebert-threshold", type=int, default=SECUREBERT_THRESHOLD)
    parser.add_argument("--window", type=int, default=WINDOW_MINUTES, help="sliding window in minutes")
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--mode", default=MODE)
    args = parser.parse_args()

    Orchestrator(
        interface=args.interface,
        eve_path=args.eve_path,
        suricata_threshold=args.suricata_threshold,
        securebert_threshold=args.securebert_threshold,
        window_minutes=args.window,
        db_path=args.db,
        mode=args.mode,
    ).run()
