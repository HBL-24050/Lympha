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


class GuardrailConfig(BaseModel):
    enabled: bool = True
    model_id: str = "ProtectAI/deberta-v3-base-prompt-injection-v2"
    threshold_instant_drop: float = 0.85
    threshold_warning: float = 0.40


class StateCacheConfig(BaseModel):
    backend: Literal["redis", "memory"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    accumulation_threshold: float = 10.0
    window_seconds: int = 3600
    decay_half_life: int = 600


class Tier2Config(BaseModel):
    enabled: bool = True
    guardrail: GuardrailConfig = Field(default_factory=GuardrailConfig)
    state_cache: StateCacheConfig = Field(default_factory=StateCacheConfig)


class Tier3Config(BaseModel):
    enabled: bool = False
    api_base: str = "http://localhost:8000/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    max_tokens: int = 2048
    trigger_threshold: float = 10.0
    system_prompt: str = (
        "You are a security analyst reviewing HTTP traffic warnings. "
        "Given a list of alerts with warning weights and tactic descriptions, "
        "determine if this traffic represents a coordinated attack. "
        "Respond with exactly one word: BLOCK if the evidence strongly indicates an attack, "
        "WARN if suspicious but inconclusive, or PASS if likely benign."
    )


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
