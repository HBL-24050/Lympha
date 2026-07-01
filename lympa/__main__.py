from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from lympa.config import AppConfig
from lympa.orchestrator import LymphaPipeline
from lympa.traffic_capture import PacketCaptureFeeder

log = logging.getLogger(__name__)


def setup_logging(config: AppConfig) -> None:
    level = getattr(logging, config.logging.level.upper(), logging.INFO)
    handlers: list[logging.Handler] = []

    if config.logging.console:
        handlers.append(logging.StreamHandler(sys.stdout))

    if config.logging.file:
        log_path = Path(config.logging.file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_path)))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


async def _feed_from_log(pipeline: LymphaPipeline, log_path: str) -> None:
    try:
        from test.feature_extractor import extract_features
    except ImportError:
        log.error("--tail requires test/feature_extractor.py (are you in the project root?)")
        return

    log.info("Tailing request log: %s", log_path)

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    proc = await asyncio.create_subprocess_exec(
        "tail", "--follow=name", "--retry", "-n", "+1", log_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    assert proc.stdout is not None
    while True:
        line = await proc.stdout.readline()
        if not line:
            await asyncio.sleep(0.5)
            continue
        try:
            record = json.loads(line.decode().strip())
        except json.JSONDecodeError:
            continue

        features = extract_features(record)
        source_ip = record.get("source_ip", "0.0.0.0")
        results = await pipeline.ingest_features(features, source_ip)
        for r in results:
            method = record.get("method", "")
            path = record.get("path", "")
            if r.verdict.name == "INSTANT_DROP":
                log.info(
                    "[BLOCKED] %s %s %s | score=%.4f | source=%s | reason=Tier1/XGBoost",
                    source_ip, method, path, r.score, r.source,
                )
            elif r.verdict.name == "WARNING":
                log.info(
                    "[WARN]    %s %s %s | score=%.4f | routing to Guardrail",
                    source_ip, method, path, r.score,
                )
            else:
                log.info(
                    "[PASS]    %s %s %s | score=%.4f",
                    source_ip, method, path, r.score,
                )


async def amain(
    config_path: str | None = None,
    tail_file: str | None = None,
    capture_iface: str | None = None,
) -> None:
    if config_path is None:
        config_path = "config.yaml"

    config = AppConfig.from_yaml(config_path)
    setup_logging(config)

    pipeline = LymphaPipeline(config)
    await pipeline.start()

    log.info("Lympha running in %s mode — press Ctrl+C to stop", config.mode)

    tasks: list[asyncio.Task] = []
    if tail_file:
        tasks.append(asyncio.create_task(_feed_from_log(pipeline, tail_file)))
    feeder: Optional[PacketCaptureFeeder] = None
    if capture_iface:
        feeder = PacketCaptureFeeder(
            interface=capture_iface,
            pipeline=pipeline,
        )
        await feeder.start()

    try:
        await asyncio.gather(
            asyncio.ensure_future(_idle_loop()),
            *tasks,
            return_exceptions=True,
        )
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        if feeder:
            await feeder.stop()
        for t in tasks:
            t.cancel()
        await pipeline.stop()


async def _idle_loop() -> None:
    while True:
        await asyncio.sleep(3600)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lympha Security Pipeline")
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration YAML (default: config.yaml)",
    )
    parser.add_argument(
        "--tail",
        default=None,
        help="Follow a server request JSONL log file and process live",
    )
    parser.add_argument(
        "--capture",
        default=None,
        help="Live packet capture interface (e.g. eth0, any; requires scapy + root)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(amain(args.config, args.tail, args.capture))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
