import logging
from pathlib import Path
from typing import Optional
import numpy as np

log = logging.getLogger(__name__)


class MambaLogStream:
    def __init__(
        self,
        model_path: str | Path,
        sequence_length: int = 512,
    ) -> None:
        self.model_path = Path(model_path)
        self.sequence_length = sequence_length
        self._model: Optional[object] = None
        self._tokenizer: Optional[object] = None

    async def load(self) -> None:
        if not self.model_path.exists():
            log.warning(
                "Mamba checkpoint not found at %s — using dummy fallback",
                self.model_path,
            )
            return
        try:
            import torch
            from mamba_ssm import MambaLMHeadModel
            from transformers import AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained("EleutherAI/gpt-neox-20b")
            self._model = MambaLMHeadModel.from_pretrained(
                str(self.model_path),
                dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device="cuda" if torch.cuda.is_available() else "cpu",
            )
            log.info("Loaded Mamba model from %s", self.model_path)
        except ImportError:
            log.warning(
                "mamba_ssm not installed — falling back to dummy scoring"
            )

    def score_log(self, log_line: str) -> float:
        if self._model is None:
            return float(np.random.uniform(0.0, 0.5))
        inputs = self._tokenizer(
            log_line,
            return_tensors="pt",
            truncation=True,
            max_length=self.sequence_length,
        )
        import torch
        with torch.no_grad():
            outputs = self._model(**inputs)
            anomaly_score = torch.sigmoid(outputs.logits.mean()).item()
        return anomaly_score
