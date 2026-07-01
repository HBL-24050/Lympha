from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import math
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import numpy as np

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
log = logging.getLogger("benchmark")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CSV_PATH = DATA_DIR / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_full.csv"


def load_dataset(limit: Optional[int] = None) -> list[tuple[dict, int]]:
    """Return list of (request_dict, label) where label=1 for anom."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            grouped[row["index"]].append(row)

    pairs: list[tuple[dict, int]] = []
    for idx, rows in grouped.items():
        norm_row = None
        anom_row = None
        for r in rows:
            if r["label"].strip() == "norm":
                norm_row = r
            else:
                anom_row = r
        if norm_row and anom_row:
            pairs.append((norm_row, 0))
            pairs.append((anom_row, 1))
        elif norm_row:
            pairs.append((norm_row, 0))
        if limit and len(pairs) >= limit:
            break

    return pairs[:limit]


def build_raw(row: dict) -> str:
    method = row.get("method", "GET")
    url = row.get("url", "/")
    protocol = row.get("protocol", "HTTP/1.1")
    host = row.get("host", "localhost")
    payload = row.get("payload", "")
    if payload == "null":
        payload = ""
    accept = row.get("accept", "*/*")
    ua = row.get("userAgent", "")
    conn = row.get("connection", "close")
    ct = row.get("contentType", "")
    cl = row.get("contentLength", "")

    parts = [f"{method} {url} {protocol}"]
    parts.append(f"Host: {host}")
    parts.append(f"User-Agent: {ua}")
    parts.append(f"Accept: {accept}")
    parts.append(f"Connection: {conn}")
    if ct and ct != "null":
        parts.append(f"Content-Type: {ct}")
    if cl and cl != "null":
        parts.append(f"Content-Length: {cl}")
    cookie = row.get("cookie", "")
    if cookie:
        parts.append(f"Cookie: {cookie}")
    parts.append("")
    if payload:
        parts.append(payload)
    return "\r\n".join(parts)


def build_req(row: dict, idx: int) -> dict:
    raw = build_raw(row)
    url = row.get("url", "/")
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = parsed.query or ""
    body = row.get("payload", "")
    if body == "null":
        body = ""
    return {
        "raw": raw,
        "path": path,
        "query": query,
        "body": body,
        "method": row.get("method", "GET"),
        "headers": {"host": row.get("host", "")},
        "source_ip": f"10.0.0.{idx % 255}",
    }


async def run_benchmark(
    limit: int = 1000,
    output: Optional[str] = None,
) -> None:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from lympa.tier2.guardrail import PromptGuardrail
    from test.feature_extractor import extract_features, reset_rate_tracker

    print(f"Loading CSIC 2010...")
    pairs = load_dataset(limit)
    print(f"  loaded {len(pairs)} rows")
    n_attacks = sum(l for _, l in pairs)
    n_benign = len(pairs) - n_attacks
    print(f"  attacks={n_attacks}  benign={n_benign}")

    print("\nLoading guardrail model...")
    t0 = time.time()
    guardrail = PromptGuardrail()
    await guardrail.load()
    print(f"  loaded in {time.time()-t0:.1f}s")

    tier2_latencies: list[float] = []
    tier2_scores: list[float] = []
    labels: list[int] = []

    reset_rate_tracker()

    print(f"\nRunning benchmark ({len(pairs)} requests)...")
    t_start = time.time()

    for i, (row, label) in enumerate(pairs):
        req = build_req(row, i)
        raw_text = build_raw(row)

        t2 = time.time()
        score, meta = guardrail.analyze(raw_text)
        tier2_latencies.append(time.time() - t2)
        tier2_scores.append(score)
        labels.append(label)

        if (i + 1) % 500 == 0:
            print(f"  {i+1}/{len(pairs)}  ({time.time()-t_start:.1f}s)")

    elapsed = time.time() - t_start
    print(f"\nDone in {elapsed:.1f}s  ({len(pairs)/elapsed:.0f} req/s)")

    # ── Metrics ──
    t2_arr = np.array(tier2_scores)
    actual = np.array(labels)

    for threshold, label_name in [(0.85, "instant_drop"), (0.40, "warning")]:
        pred = (t2_arr >= threshold).astype(int)
        tp = int(np.sum((pred == 1) & (actual == 1)))
        fp = int(np.sum((pred == 1) & (actual == 0)))
        fn = int(np.sum((pred == 0) & (actual == 1)))
        tn = int(np.sum((pred == 0) & (actual == 0)))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

        print(f"\n  Tier 2 @ {label_name} (≥{threshold}):")
        print(f"    TP={tp:5d}  FP={fp:5d}")
        print(f"    FN={fn:5d}  TN={tn:5d}")
        print(f"    precision={prec:.4f}  recall={rec:.4f}  F1={f1:.4f}")

    for p in [50, 95, 99]:
        val = np.percentile(tier2_latencies, p) * 1000
        if p == 50:
            print(f"\n  Latency (Tier 2): p{p}={val:.1f}ms")
        else:
            print(f"                   p{p}={val:.1f}ms")
    print(f"                   mean={np.mean(tier2_latencies)*1000:.1f}ms")

    benign_scores = [s for s, l in zip(tier2_scores, labels) if l == 0]
    attack_scores = [s for s, l in zip(tier2_scores, labels) if l == 1]

    print(f"\n  Benign scores:  mean={np.mean(benign_scores):.4f}  >0.40={sum(1 for s in benign_scores if s>=0.40)}/{len(benign_scores)}  >0.85={sum(1 for s in benign_scores if s>=0.85)}/{len(benign_scores)}")
    print(f"  Attack scores:  mean={np.mean(attack_scores):.4f}  >0.40={sum(1 for s in attack_scores if s>=0.40)}/{len(attack_scores)}  >0.85={sum(1 for s in attack_scores if s>=0.85)}/{len(attack_scores)}")

    if output:
        import json
        report = {
            "limit": len(pairs),
            "elapsed_seconds": round(elapsed, 2),
            "requests_per_second": round(len(pairs) / elapsed, 1),
            "n_attacks": n_attacks,
            "n_benign": n_benign,
            "latency_ms": {
                "p50": round(np.percentile(tier2_latencies, 50) * 1000, 1),
                "p95": round(np.percentile(tier2_latencies, 95) * 1000, 1),
                "p99": round(np.percentile(tier2_latencies, 99) * 1000, 1),
                "mean": round(np.mean(tier2_latencies) * 1000, 1),
            },
        }
        for threshold, label_name in [(0.85, "instant_drop"), (0.40, "warning")]:
            pred = (t2_arr >= threshold).astype(int)
            tp = int(np.sum((pred == 1) & (actual == 1)))
            fp = int(np.sum((pred == 1) & (actual == 0)))
            fn = int(np.sum((pred == 0) & (actual == 1)))
            tn = int(np.sum((pred == 0) & (actual == 0)))
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
            report[label_name] = {
                "threshold": threshold,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
            }
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CSIC 2010 benchmark for Prompt Guardrail")
    parser.add_argument("--limit", "-n", type=int, default=1000, help="number of requests")
    parser.add_argument("--output", "-o", type=str, default=None, help="save report JSON")
    args = parser.parse_args()
    asyncio.run(run_benchmark(limit=args.limit, output=args.output))


if __name__ == "__main__":
    main()
