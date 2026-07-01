from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import numpy as np

from lympa.tier1.xgboost_model import XGBoostAnomalyDetector
from lympa.tier1.mamba_stream import MambaLogStream

log = logging.getLogger(__name__)


class Verdict(Enum):
    PASS = auto()
    WARNING = auto()
    INSTANT_DROP = auto()


@dataclass
class Tier1Result:
    verdict: Verdict
    score: float
    source_ip: str
    source: str  # "xgboost" | "mamba"
    raw_data: Optional[str] = None
    features: Optional[np.ndarray] = None


@dataclass
class Tier1Engine:
    xgboost: XGBoostAnomalyDetector
    mamba: MambaLogStream
    xgb_instant: float
    xgb_warning: float
    mamba_instant: float
    mamba_warning: float

    async def load_models(self) -> None:
        await self.xgboost.load()
        await self.mamba.load()

    def evaluate_xgboost(self, features: np.ndarray, source_ip: str) -> list[Tier1Result]:
        scores = self.xgboost.predict(features)
        results: list[Tier1Result] = []
        for i in range(features.shape[0]):
            score = float(scores[i])
            verdict = self._threshold(score, self.xgb_instant, self.xgb_warning)
            results.append(Tier1Result(
                verdict=verdict,
                score=score,
                source_ip=source_ip,
                source="xgboost",
                features=features[i],
            ))
        return results

    def evaluate_mamba(self, log_lines: list[str], source_ip: str) -> list[Tier1Result]:
        results: list[Tier1Result] = []
        for line in log_lines:
            score = self.mamba.score_log(line)
            verdict = self._threshold(score, self.mamba_instant, self.mamba_warning)
            results.append(Tier1Result(
                verdict=verdict,
                score=score,
                source_ip=source_ip,
                source="mamba",
                raw_data=line,
            ))
        return results

    @staticmethod
    def _threshold(score: float, instant: float, warning: float) -> Verdict:
        if score >= instant:
            return Verdict.INSTANT_DROP
        if score >= warning:
            return Verdict.WARNING
        return Verdict.PASS
