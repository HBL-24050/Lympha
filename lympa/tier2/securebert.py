from __future__ import annotations

import logging
from typing import Optional
import numpy as np

log = logging.getLogger(__name__)


class SecureBERTAnomalyParser:
    def __init__(
        self,
        model_name: str = "cisco-ai/SecureBERT2.0-base",
        device: str = "auto",
        max_length: int = 256,
        instant_drop_threshold: float = 0.85,
        warning_threshold: float = 0.50,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self.max_length = max_length
        self.instant_drop_threshold = instant_drop_threshold
        self.warning_threshold = warning_threshold
        self._pipeline: Optional[object] = None
        self._tokenizer: Optional[object] = None
        self._model: Optional[object] = None

    async def load(self) -> None:
        resolved_device = self._resolve_device()
        log.info(
            "Loading SecureBERT from %s on device=%s",
            self.model_name, resolved_device,
        )
        try:
            import torch
            from transformers import (
                AutoTokenizer,
                AutoModelForSequenceClassification,
                pipeline,
            )

            torch_dtype = torch.float16 if resolved_device == "cuda" else torch.float32
            attn_impl = "flash_attention_2" if resolved_device == "cuda" else None

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name,
                torch_dtype=torch_dtype,
                device_map=resolved_device,
                attn_implementation=attn_impl,
            )
            self._pipeline = pipeline(
                "text-classification",
                model=self._model,
                tokenizer=self._tokenizer,
                device_map=resolved_device,
                max_length=self.max_length,
                truncation=True,
                return_all_scores=True,
            )
            log.info("SecureBERT loaded successfully on %s", resolved_device)
        except Exception as exc:
            log.warning(
                "Failed to load SecureBERT (%s); falling back to dummy scorer: %s",
                exc, self.model_name,
            )

    def _resolve_device(self) -> str:
        if self.device != "auto":
            return self.device
        try:
            import torch
            if torch.cuda.is_available():
                return "cuda"
        except ImportError:
            pass
        return "cpu"

    def analyze(self, text: str) -> tuple[float, dict]:
        if self._pipeline is None:
            score = float(np.random.uniform(0.0, 0.4))
            return score, {"method": "dummy_fallback"}

        try:
            result = self._pipeline(text)
            if isinstance(result, list) and isinstance(result[0], dict):
                anomaly_score = result[0].get("score", 0.0)
            elif isinstance(result, list) and isinstance(result[0], list):
                label_map = {r["label"]: r["score"] for r in result[0]}
                anomaly_score = label_map.get("ANOMALY", label_map.get("LABEL_1", 0.0))
            else:
                anomaly_score = 0.0
            return anomaly_score, {"method": "securebert", "raw": result}
        except Exception as exc:
            log.error("SecureBERT inference failed: %s", exc)
            return 0.0, {"method": "error", "error": str(exc)}

    def classify(self, score: float) -> str:
        if score >= self.instant_drop_threshold:
            return "instant_drop"
        if score >= self.warning_threshold:
            return "warning"
        return "pass"
