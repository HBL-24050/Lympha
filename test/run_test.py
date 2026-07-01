from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import random

from lympa.config import AppConfig
from lympa.orchestrator import LymphaPipeline
from lympa.tier1.engine import Verdict
from test.attack import all_attacks, all_benign
from test.feature_extractor import extract_features, reset_rate_tracker
from test.vuln_server import REQUEST_LOG, VulnServer

log = logging.getLogger("test_runner")


async def send_request(client: httpx.AsyncClient, url: str, req: dict) -> str:
    method = req.get("method", "GET")
    path = req.get("path", "/")
    query = req.get("query", "")
    body = req.get("body", None)

    full_url = f"{url}{path}"
    if query:
        full_url = f"{full_url}?{query}"

    headers = {"User-Agent": "LymphaTest/1.0"}
    content = body.encode() if body else None

    try:
        resp = await client.request(method, full_url, headers=headers, content=content, timeout=5)
        return resp.text
    except Exception as e:
        return f"ERROR: {e}"


async def run_test() -> None:
    Path("logs").mkdir(exist_ok=True)

    config = AppConfig.from_yaml("config.yaml")
    config.logging.file = "logs/test_run.log"
    config.logging.console = False

    pipeline = LymphaPipeline(config)
    server = VulnServer(host="127.0.0.1", port=8080)

    log.info("Starting vulnerable server and pipeline...")
    await server.start()
    await pipeline.start()

    reset_rate_tracker()
    REQUEST_LOG.clear()

    client = httpx.AsyncClient()

    attacks = all_attacks()
    benign = all_benign()

    print("\n" + "=" * 80)
    print("  Lympha Pipeline — Security Test Run")
    print("=" * 80)
    print(f"  Mode:           {config.mode}")
    print(f"  Server URL:     {server.url}")
    print(f"  Attacks:        {len(attacks)}")
    print(f"  Benign:         {len(benign)}")
    print("=" * 80)

    all_requests: list[dict] = []
    all_requests.extend(attacks)
    all_requests.extend(benign)
    random.shuffle(all_requests)

    results: list[dict] = []
    for i, req in enumerate(all_requests):
        resp_text = await send_request(client, server.url, req)

        if REQUEST_LOG:
            record = REQUEST_LOG.pop(0)
        else:
            record = {
                "source_ip": "127.0.0.1",
                "raw": json.dumps(req),
                "method": req.get("method", "GET"),
                "path": req.get("path", "/"),
                "query": req.get("query", ""),
                "body": req.get("body", ""),
                "headers": {},
            }

        features = extract_features(record)

        tier1_results = await pipeline.ingest_features(features, record["source_ip"])

        verdict = "PASS"
        t1_score = 0.0
        if tier1_results:
            t1_score = tier1_results[0].score
            verdict = tier1_results[0].verdict.name

        t2_score = 0.0
        t2_label = ""
        if verdict == "WARNING":
            raw_text = f"{req.get('method','')} {req.get('path','')} {req.get('body','')}"
            t2_score, t2_meta = pipeline.guardrail.analyze(raw_text)
            t2_label = pipeline.guardrail.classify(t2_score)
            if t2_label == "instant_drop":
                verdict = "INSTANT_DROP"
                await pipeline.iptables.block_ip(
                    record["source_ip"],
                    reason=f"Tier2/Guardrail score={t2_score:.4f}",
                )
                t2_label = "caught_by_tier2"

        results.append({
            "index": i,
            "type": req.get("type", "unknown"),
            "method": req.get("method", "GET"),
            "path": req.get("path", "/"),
            "verdict": verdict,
            "t1_score": t1_score,
            "t2_score": t2_score,
            "t2_label": t2_label,
            "response": resp_text[:80],
        })

        await asyncio.sleep(0.02)

    await client.aclose()
    await pipeline.stop()
    await server.stop()

    # ── Summary table ───────────────────────────────────────────
    print(f"\n{'Type':<25} {'Total':>6} {'Blocked':>8} {'Warned':>8} {'Passed':>8} {'BlockRate':>10}")
    print("-" * 65)

    categories: dict[str, list[dict]] = {}
    for r in results:
        cat = r["type"].rsplit("_", 1)[0] if "_" in r["type"] else r["type"]
        categories.setdefault(cat, []).append(r)

    total_blocked = 0
    total_warned = 0
    for cat, items in sorted(categories.items()):
        total = len(items)
        blocked = sum(1 for r in items if r["verdict"] == "INSTANT_DROP")
        warned = sum(1 for r in items if r["verdict"] == "WARNING")
        passed = total - blocked - warned
        total_blocked += blocked
        total_warned += warned
        rate = blocked / total * 100 if total > 0 else 0
        print(f"{cat:<25} {total:>6} {blocked:>8} {warned:>8} {passed:>8} {rate:>8.1f}%")

    print("-" * 65)
    total = len(results)
    passed = total - total_blocked - total_warned
    print(f"{'TOTAL':<25} {total:>6} {total_blocked:>8} {total_warned:>8} {passed:>8} {total_blocked / total * 100 if total > 0 else 0:>8.1f}%")

    # ── Detail samples ──────────────────────────────────────────
    print("\n  Tier 1 INSTANT_DROP (first 5):")
    for r in results:
        if r["verdict"] == "INSTANT_DROP" and r.get("t2_label") != "caught_by_tier2":
            print(f"    [{r['type']}] {r['method']} {r['path']}  t1={r['t1_score']:.4f}")
            break
    for r in results:
        if r["verdict"] == "INSTANT_DROP" and r.get("t2_label") != "caught_by_tier2" and r["index"] % 4 == 0:
            print(f"    [{r['type']}] {r['method']} {r['path']}  t1={r['t1_score']:.4f}")

    caught_by_t2 = [r for r in results if r.get("t2_label") == "caught_by_tier2"]
    if caught_by_t2:
        print(f"\n  Tier 2 escalated to block ({len(caught_by_t2)}):")
        for r in caught_by_t2[:3]:
            print(f"    [{r['type']}] {r['method']} {r['path']}  t1={r['t1_score']:.4f}  t2={r['t2_score']:.4f}")

    passed_items = [r for r in results if r["verdict"] == "PASS"]
    if passed_items:
        print(f"\n  PASS (benign ignored):")
        for r in passed_items[:5]:
            print(f"    [{r['type']}] {r['method']} {r['path']}  t1={r['t1_score']:.4f}")

    print()

    print("  Summary:")
    print(f"    Tier 1 (XGBoost) blocked:    {total_blocked}")
    print(f"    Tier 2 (Guardrail) blocked: {len(caught_by_t2)}")
    print(f"    Still in state cache:        {total_warned}")
    print(f"    Clean passed:                {passed}")


def main() -> None:
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    asyncio.run(run_test())


if __name__ == "__main__":
    main()
