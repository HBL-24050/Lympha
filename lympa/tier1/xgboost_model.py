import logging
from pathlib import Path
from typing import Optional
import numpy as np
import xgboost as xgb

log = logging.getLogger(__name__)


class XGBoostAnomalyDetector:
    def __init__(self, model_path: str | Path, feature_dim: int = 48) -> None:
        self.model_path = Path(model_path)
        self.feature_dim = feature_dim
        self._booster: Optional[xgb.Booster] = None

    async def load(self) -> None:
        if not self.model_path.exists():
            log.warning(
                "XGBoost model not found at %s — using dummy fallback",
                self.model_path,
            )
            return
        self._booster = xgb.Booster()
        self._booster.load_model(str(self.model_path))
        log.info("Loaded XGBoost model from %s", self.model_path)

    def predict(self, features: np.ndarray) -> np.ndarray:
        if self._booster is None:
            return np.random.uniform(0.0, 0.5, size=(features.shape[0],))
        dmat = xgb.DMatrix(features)
        scores = self._booster.predict(dmat)
        return scores
