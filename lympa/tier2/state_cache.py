from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from lympa.config import StateCacheConfig

log = logging.getLogger(__name__)


@dataclass
class WarningRecord:
    source_ip: str
    target_subnet: str
    tactic_vector: str
    warning_weight: float
    timestamp: float = field(default_factory=time.time)


class MemoryStateCache:
    def __init__(
        self,
        accumulation_threshold: float = 10.0,
        window_seconds: int = 3600,
        decay_half_life: int = 600,
    ) -> None:
        self._records: list[WarningRecord] = []
        self.accumulation_threshold = accumulation_threshold
        self.window_seconds = window_seconds
        self.decay_half_life = decay_half_life

    def push(self, record: WarningRecord) -> None:
        self._garbage_collect()
        self._records.append(record)
        log.debug(
            "Cache push: IP=%s subnet=%s weight=%.3f total=%.3f",
            record.source_ip, record.target_subnet,
            record.warning_weight, self.total_weight(),
        )

    def total_weight(self) -> float:
        self._garbage_collect()
        now = time.time()
        total = 0.0
        for r in self._records:
            age = now - r.timestamp
            decay = 2.0 ** (-age / self.decay_half_life) if self.decay_half_life > 0 else 1.0
            total += r.warning_weight * decay
        return total

    def breached(self) -> bool:
        return self.total_weight() >= self.accumulation_threshold

    def weight_by_subnet(self) -> dict[str, float]:
        self._garbage_collect()
        now = time.time()
        subnets: dict[str, float] = {}
        for r in self._records:
            age = now - r.timestamp
            decay = 2.0 ** (-age / self.decay_half_life) if self.decay_half_life > 0 else 1.0
            subnets[r.target_subnet] = subnets.get(r.target_subnet, 0.0) + r.warning_weight * decay
        return subnets

    def weight_by_source_ip(self) -> dict[str, float]:
        self._garbage_collect()
        now = time.time()
        ips: dict[str, float] = {}
        for r in self._records:
            age = now - r.timestamp
            decay = 2.0 ** (-age / self.decay_half_life) if self.decay_half_life > 0 else 1.0
            ips[r.source_ip] = ips.get(r.source_ip, 0.0) + r.warning_weight * decay
        return ips

    def top_subnets(self, n: int = 5) -> list[tuple[str, float]]:
        return sorted(self.weight_by_subnet().items(), key=lambda x: -x[1])[:n]

    def reset(self) -> None:
        self._records.clear()

    def _garbage_collect(self) -> None:
        now = time.time()
        cutoff = now - self.window_seconds
        self._records = [r for r in self._records if r.timestamp >= cutoff]


class RedisStateCache:
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        accumulation_threshold: float = 10.0,
        window_seconds: int = 3600,
        decay_half_life: int = 600,
    ) -> None:
        self.redis_url = redis_url
        self.accumulation_threshold = accumulation_threshold
        self.window_seconds = window_seconds
        self.decay_half_life = decay_half_life
        self._redis: Optional[object] = None

    async def connect(self) -> None:
        try:
            from redis.asyncio import from_url
            self._redis = await from_url(self.redis_url, decode_responses=True)
            log.info("Connected to Redis at %s", self.redis_url)
        except ImportError:
            log.warning("redis-py not installed; falling back to MemoryStateCache")
        except Exception as exc:
            log.warning("Redis connection failed (%s); falling back to MemoryStateCache", exc)

    async def push(self, record: WarningRecord) -> None:
        if self._redis is None:
            return
        key = f"lympa:record:{record.source_ip}:{int(record.timestamp * 1000)}"
        payload = json.dumps({
            "source_ip": record.source_ip,
            "target_subnet": record.target_subnet,
            "tactic_vector": record.tactic_vector,
            "warning_weight": record.warning_weight,
            "timestamp": record.timestamp,
        })
        await self._redis.setex(key, self.window_seconds, payload)
        await self._redis.zadd("lympa:records", {key: record.timestamp})

    async def total_weight(self) -> float:
        if self._redis is None:
            return 0.0
        now = time.time()
        cutoff = now - self.window_seconds
        keys = await self._redis.zrangebyscore("lympa:records", cutoff, now)
        total = 0.0
        for key in keys:
            raw = await self._redis.get(key)
            if raw is None:
                continue
            data = json.loads(raw)
            age = now - data["timestamp"]
            decay = 2.0 ** (-age / self.decay_half_life) if self.decay_half_life > 0 else 1.0
            total += data["warning_weight"] * decay
        return total

    async def breached(self) -> bool:
        return await self.total_weight() >= self.accumulation_threshold

    async def weight_by_subnet(self) -> dict[str, float]:
        return await self._aggregate("target_subnet")

    async def weight_by_source_ip(self) -> dict[str, float]:
        return await self._aggregate("source_ip")

    async def _aggregate(self, field: str) -> dict[str, float]:
        if self._redis is None:
            return {}
        now = time.time()
        cutoff = now - self.window_seconds
        keys = await self._redis.zrangebyscore("lympa:records", cutoff, now)
        groups: dict[str, float] = {}
        for key in keys:
            raw = await self._redis.get(key)
            if raw is None:
                continue
            data = json.loads(raw)
            age = now - data["timestamp"]
            decay = 2.0 ** (-age / self.decay_half_life) if self.decay_half_life > 0 else 1.0
            g = data[field]
            groups[g] = groups.get(g, 0.0) + data["warning_weight"] * decay
        return groups

    async def reset(self) -> None:
        if self._redis is None:
            return
        await self._redis.delete("lympa:records")


def create_state_cache(config: StateCacheConfig) -> MemoryStateCache | RedisStateCache:
    if config.backend == "redis":
        return RedisStateCache(
            redis_url=config.redis_url,
            accumulation_threshold=config.accumulation_threshold,
            window_seconds=config.window_seconds,
            decay_half_life=config.decay_half_life,
        )
    return MemoryStateCache(
        accumulation_threshold=config.accumulation_threshold,
        window_seconds=config.window_seconds,
        decay_half_life=config.decay_half_life,
    )
