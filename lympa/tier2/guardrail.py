from __future__ import annotations

import logging
from typing import Optional

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

log = logging.getLogger(__name__)


class PromptGuardrail:
    def __init__(
        self,
        instant_drop_threshold: float = 0.85,
        warning_threshold: float = 0.40,
        model_id: str = "ProtectAI/deberta-v3-base-prompt-injection-v2",
    ) -> None:
        self.instant_drop_threshold = instant_drop_threshold
        self.warning_threshold = warning_threshold
        self.model_id = model_id
        self._loaded = False
        self._model: Optional[AutoModelForSequenceClassification] = None
        self._tokenizer: Optional[AutoTokenizer] = None

    async def load(self) -> None:
        log.info("Loading prompt guardrail model %s ...", self.model_id)
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
        self._model.eval()
        self._loaded = True
        log.info("Prompt guardrail model loaded")

    def analyze(self, text: str) -> tuple[float, dict]:
        if not self._loaded or self._model is None or self._tokenizer is None:
            return 0.0, {"method": "not_loaded"}

        inputs = self._tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512
        )
        with torch.no_grad():
            outputs = self._model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)
        score = probs[0, 1].item()

        return score, {
            "method": "deberta_prompt_injection",
            "model": self.model_id,
            "injection_probability": round(score, 4),
            "safe_probability": round(probs[0, 0].item(), 4),
        }

    def classify(self, score: float) -> str:
        if score >= self.instant_drop_threshold:
            return "instant_drop"
        if score >= self.warning_threshold:
            return "warning"
        return "pass"