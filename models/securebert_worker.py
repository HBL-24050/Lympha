import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

from scapy.all import IP, Raw, TCP, sniff

from core.config import HTTP_PORTS, INTERFACE, SECUREBERT_MODEL, SECUREBERT_SCORE_THRESHOLD


SUSPICIOUS_PATTERNS = [
    re.compile(r"(\b|\s)(exec|cmd|bash|sh|powershell|wget|curl)\s", re.I),
    re.compile(r"(union|select|from|where|drop|delete|insert|update)\s+.*\s+(from|into|set)", re.I),
    re.compile(r"(\.\.\/|\/etc\/passwd|\/proc\/self)", re.I),
    re.compile(r"(<script|alert\(|onerror=|onload=)", re.I),
    re.compile(r"(SELECT\s+.+\s+FROM|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE)", re.I),
    re.compile(r"(admin|root)\s*=\s*(true|1)", re.I),
]


@dataclass
class PayloadResult:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    method: str
    path: str
    text_snippet: str
    anomaly_score: float


class SecureBERTWorker:
    def __init__(
        self,
        model_name: str = SECUREBERT_MODEL,
        threshold: float = SECUREBERT_SCORE_THRESHOLD,
        device: str = "cpu",
    ):
        self.model_name = model_name
        self.threshold = threshold
        self.device = device
        self.model = None
        self.tokenizer = None
        self._load_model()

    def _load_model(self):
        try:
            from transformers import RobertaModel, RobertaTokenizer

            self.tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
            self.model = RobertaModel.from_pretrained(self.model_name).to(self.device)
            self.model.eval()
        except Exception as exc:
            pass  # status is reported in the orchestrator startup banner

    def _heuristic_score(self, text: str) -> float:
        if not text:
            return 0.0
        score = 0.0
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(text):
                score += 1.0 / len(SUSPICIOUS_PATTERNS)
        return min(score, 1.0)

    def classify_text(self, text: str) -> float:
        heuristic = self._heuristic_score(text)

        if self.model is None:
            return heuristic

        import torch

        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            cls_embedding = outputs.last_hidden_state[:, 0, :]
            norm = torch.norm(cls_embedding, dim=-1).item()
            model_score = min(norm / 15.0, 1.0)

        return 0.3 * model_score + 0.7 * heuristic

    def extract_http_payload(self, packet) -> Optional[dict]:
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None
        try:
            raw = packet[Raw].load.decode("utf-8", errors="ignore")
            lines = raw.split("\r\n")
            if not lines:
                return None
            first = lines[0]
            if not any(
                first.startswith(m)
                for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            ):
                return None
            parts = first.split(" ")
            return {
                "method": parts[0],
                "path": parts[1] if len(parts) > 1 else "/",
                "headers": "\n".join(lines[1:]),
                "raw": raw[:2000],
            }
        except Exception:
            return None

    def start_sniffing(
        self,
        callback: Callable[[PayloadResult], None],
        interface: str = INTERFACE,
        packet_count: int = 0,
        timeout: Optional[float] = None,
    ):
        iface = interface

        def handler(pkt):
            extracted = self.extract_http_payload(pkt)
            if not extracted:
                return

            text = f"{extracted['method']} {extracted['path']}\n{extracted['headers']}"
            score = self.classify_text(text)

            result = PayloadResult(
                timestamp=datetime.now(),
                source_ip=pkt[IP].src,
                destination_ip=pkt[IP].dst,
                method=extracted["method"],
                path=extracted["path"],
                text_snippet=extracted["raw"][:500],
                anomaly_score=score,
            )

            if score >= self.threshold:
                callback(result)

        sniff(
            filter=f"tcp port {HTTP_PORTS}",
            prn=handler,
            store=0,
            count=packet_count,
            timeout=timeout,
            iface=iface,
        )
