from pathlib import Path
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator
import yaml
import logging

log = logging.getLogger(__name__)


class XGBoostConfig(BaseModel):
    model_path: str = "models/tier1/xgboost_model.json"
    feature_dim: int = 48
    threshold_instant_drop: float = 0.92
    threshold_warning: float = 0.70


class MambaConfig(BaseModel):
    model_path: str = "models/tier1/mamba_state_dict.pt"
    sequence_length: int = 512
    threshold_instant_drop: float = 0.90
    threshold_warning: float = 0.65


class Tier1Config(BaseModel):
    enabled: bool = True
    xgboost: XGBoostConfig = Field(default_factory=XGBoostConfig)
    mamba: MambaConfig = Field(default_factory=MambaConfig)
    cooldown_seconds: int = 300


class CodeBERTConfig(BaseModel):
    model_name: str = "microsoft/codebert-base"
    cache_dir: str = "models/tier2"
    device: Literal["auto", "cuda", "cpu"] = "auto"
    max_length: int = 256
    threshold_instant_drop: float = 0.85
    threshold_warning: float = 0.50


class StateCacheConfig(BaseModel):
    backend: Literal["redis", "memory"] = "redis"
    redis_url: str = "redis://localhost:6379/0"
    accumulation_threshold: float = 10.0
    window_seconds: int = 3600
    decay_half_life: int = 600


class Tier2Config(BaseModel):
    enabled: bool = True
    codebert: CodeBERTConfig = Field(default_factory=CodeBERTConfig)
    state_cache: StateCacheConfig = Field(default_factory=StateCacheConfig)


class Tier3Config(BaseModel):
    enabled: bool = False
    api_base: str = "http://localhost:8000/v1"
    api_key: str = ""
    model: str = "Foundation-Sec-8B-Reasoning"
    max_tokens: int = 2048
    trigger_threshold: float = 10.0


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    file: Optional[str] = "logs/lympa.log"
    console: bool = True


class InterfaceConfig(BaseModel):
    capture: str = "eth0"
    control: str = "eth0"


class AppConfig(BaseModel):
    mode: Literal["test", "production"] = "test"
    interfaces: InterfaceConfig = Field(default_factory=InterfaceConfig)
    tier1: Tier1Config = Field(default_factory=Tier1Config)
    tier2: Tier2Config = Field(default_factory=Tier2Config)
    tier3: Tier3Config = Field(default_factory=Tier3Config)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("test", "production"):
            raise ValueError(f"mode must be 'test' or 'production', got '{v}'")
        return v

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AppConfig":
        path = Path(path)
        if not path.exists():
            log.warning("Config file %s not found, using defaults", path)
            return cls()
        with open(path) as f:
            raw = yaml.safe_load(f)
        if raw is None:
            return cls()
        return cls.model_validate(raw)

    def is_production(self) -> bool:
        return self.mode == "production"

    def is_test(self) -> bool:
        return self.mode == "test"
