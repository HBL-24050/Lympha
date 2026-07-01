from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional
import numpy as np

from lympa.config import AppConfig
from lympa.iptables import IptablesManager
from lympa.tier1.engine import Tier1Engine, Tier1Result, Verdict
from lympa.tier1.xgboost_model import XGBoostAnomalyDetector
from lympa.tier1.mamba_stream import MambaLogStream
from lympa.tier2.codebert import CodeBERTAnomalyParser
from lympa.tier2.state_cache import (
    WarningRecord,
    create_state_cache,
    MemoryStateCache,
    RedisStateCache,
)

log = logging.getLogger(__name__)


class LymphaPipeline:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._running = False

        c1 = config.tier1
        self.tier1 = Tier1Engine(
            xgboost=XGBoostAnomalyDetector(
                model_path=c1.xgboost.model_path,
                feature_dim=c1.xgboost.feature_dim,
            ),
            mamba=MambaLogStream(
                model_path=c1.mamba.model_path,
                sequence_length=c1.mamba.sequence_length,
            ),
            xgb_instant=c1.xgboost.threshold_instant_drop,
            xgb_warning=c1.xgboost.threshold_warning,
            mamba_instant=c1.mamba.threshold_instant_drop,
            mamba_warning=c1.mamba.threshold_warning,
        )

        c2 = config.tier2
        self.codebert = CodeBERTAnomalyParser(
            model_name=c2.codebert.model_name,
            cache_dir=c2.codebert.cache_dir,
            device=c2.codebert.device,
            max_length=c2.codebert.max_length,
            instant_drop_threshold=c2.codebert.threshold_instant_drop,
            warning_threshold=c2.codebert.threshold_warning,
        )

        self.state_cache = create_state_cache(c2.state_cache)

        self.iptables = IptablesManager(
            control_interface=config.interfaces.control,
            mode=config.mode,
        )

        self._cooldown_seconds = c1.cooldown_seconds
        self._blocked_ips: dict[str, asyncio.Task] = {}

    async def start(self) -> None:
        self._running = True
        log.info(
            "Lympha pipeline starting — mode=%s",
            self.config.mode,
        )

        await self.iptables.ensure_chain()

        if self.config.tier1.enabled:
            await self.tier1.load_models()

        if self.config.tier2.enabled:
            await self.codebert.load()

        if isinstance(self.state_cache, RedisStateCache):
            await self.state_cache.connect()

    async def stop(self) -> None:
        self._running = False
        log.info("Lympha pipeline stopped")

    async def ingest_features(
        self,
        features: np.ndarray,
        source_ip: str,
    ) -> list[Tier1Result]:
        if not self.config.tier1.enabled:
            return []
        if features.ndim == 1:
            features = features.reshape(1, -1)
        results = self.tier1.evaluate_xgboost(features, source_ip)
        await self._process_tier1_results(results)
        return results

    async def ingest_logs(
        self,
        log_lines: list[str],
        source_ip: str,
    ) -> list[Tier1Result]:
        if not self.config.tier1.enabled:
            return []
        results = self.tier1.evaluate_mamba(log_lines, source_ip)
        await self._process_tier1_results(results)
        return results

    async def _process_tier1_results(self, results: list[Tier1Result]) -> None:
        for result in results:
            if result.verdict == Verdict.INSTANT_DROP:
                await self._handle_instant_drop(result)
            elif result.verdict == Verdict.WARNING:
                await self._handle_warning(result)

    async def _handle_instant_drop(self, result: Tier1Result) -> None:
        ip = result.source_ip
        reason = (
            f"Tier1/{result.source} score={result.score:.4f}"
        )
        blocked = await self.iptables.block_ip(ip, reason=reason)
        if blocked:
            self._schedule_unblock(ip)

    async def _handle_warning(self, result: Tier1Result) -> None:
        if not self.config.tier2.enabled:
            return

        raw_text = result.raw_data or ""
        if result.features is not None:
            raw_text = f"feature_vector: {result.features.tolist()}"

        score, meta = self.codebert.analyze(raw_text)
        classification = self.codebert.classify(score)

        if classification == "instant_drop":
            reason = (
                f"Tier2/CodeBERT score={score:.4f} "
                f"(escalated from Tier1/{result.source})"
            )
            blocked = await self.iptables.block_ip(result.source_ip, reason=reason)
            if blocked:
                self._schedule_unblock(result.source_ip)
        elif classification == "warning":
            record = WarningRecord(
                source_ip=result.source_ip,
                target_subnet=self._derive_subnet(result.source_ip),
                tactic_vector=self._derive_tactic(meta),
                warning_weight=score,
            )
            self.state_cache.push(record)

            if isinstance(self.state_cache, (MemoryStateCache, RedisStateCache)):
                total = (
                    self.state_cache.total_weight()
                    if isinstance(self.state_cache, MemoryStateCache)
                    else await self.state_cache.total_weight()
                )
                log.info(
                    "State cache updated: IP=%s weight=%.3f total=%.3f/%s",
                    result.source_ip, score, total,
                    self.config.tier2.state_cache.accumulation_threshold,
                )

    def _schedule_unblock(self, ip: str) -> None:
        if ip in self._blocked_ips:
            self._blocked_ips[ip].cancel()
        task = asyncio.create_task(self._delayed_unblock(ip))
        self._blocked_ips[ip] = task

    async def _delayed_unblock(self, ip: str) -> None:
        await asyncio.sleep(self._cooldown_seconds)
        await self.iptables.unblock_ip(ip)
        self._blocked_ips.pop(ip, None)

    @staticmethod
    def _derive_subnet(ip: str) -> str:
        if "." in ip:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "0.0.0.0/0"

    @staticmethod
    def _derive_tactic(meta: dict) -> str:
        label = meta.get("method", "unknown")
        return f"anomaly_{label}"
