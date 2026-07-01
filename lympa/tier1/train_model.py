from __future__ import annotations

import argparse
import csv
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import xgboost as xgb

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("train_tier1")

ROOT = Path(__file__).resolve().parent.parent.parent
CSV_PATH = ROOT / "data" / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_full.csv"
MODEL_OUT = ROOT / "models/tier1/xgboost_model.json"


def build_req(row: dict, idx: int) -> dict:
    url = row.get("url", "/")
    parsed = urlparse(url)
    body = row.get("payload", "")
    if body == "null":
        body = ""
    method = row.get("method", "GET")
    raw = f"{method} {url} HTTP/1.1\r\nHost: {row.get('host', 'localhost')}\r\n\r\n{body}"
    return {
        "raw": raw,
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "body": body,
        "method": method,
        "headers": {"host": row.get("host", "")},
        "source_ip": f"10.0.0.{idx % 255}",
    }


def load_csic_pairs(limit: int | None = None) -> tuple[np.ndarray, np.ndarray]:
    sys.path.insert(0, str(ROOT))
    from test.feature_extractor import extract_features, reset_rate_tracker

    reset_rate_tracker()

    grouped: dict[str, list[dict]] = defaultdict(list)
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            grouped[row["index"]].append(row)

    features, labels = [], []
    count = 0
    for rows in grouped.values():
        norm_row = anom_row = None
        for r in rows:
            if r["label"].strip() == "norm":
                norm_row = r
            else:
                anom_row = r
        if norm_row and anom_row:
            features.append(extract_features(build_req(norm_row, count)))
            labels.append(0)
            count += 1
            features.append(extract_features(build_req(anom_row, count)))
            labels.append(1)
            count += 1
        elif norm_row:
            features.append(extract_features(build_req(norm_row, count)))
            labels.append(0)
            count += 1
        if limit and count >= limit:
            break

    return np.array(features, dtype=np.float32), np.array(labels)


def main(limit: int, test_split: float) -> None:
    log.info("Loading CSIC 2010 dataset (limit=%s)...", limit or "all")
    t0 = time.time()
    X, y = load_csic_pairs(limit)
    elapsed = time.time() - t0
    log.info("Loaded %d samples in %.0fs  (%d attack, %d benign)",
             len(X), elapsed, int(y.sum()), int((1 - y).sum()))

    n = len(X)
    perm = np.random.RandomState(42).permutation(n)
    X, y = X[perm], y[perm]

    split = int(n * (1 - test_split))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    log.info("Train: %d  Test: %d  (attack ratio train=%.2f  test=%.2f)",
             len(X_train), len(X_test),
             y_train.mean(), y_test.mean())

    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)

    params = {
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "max_depth": 8,
        "eta": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "min_child_weight": 3,
        "scale_pos_weight": (1 - y_train.mean()) / y_train.mean(),
    }

    log.info("Training XGBoost...")
    t0 = time.time()
    booster = xgb.train(
        params,
        dtrain,
        num_boost_round=500,
        evals=[(dtrain, "train"), (dtest, "test")],
        early_stopping_rounds=30,
        verbose_eval=50,
    )
    elapsed = time.time() - t0
    log.info("Training done in %.0fs  (best iteration=%d  best score=%.4f)",
             elapsed, booster.best_iteration, booster.best_score)

    pred_train = booster.predict(dtrain)
    pred_test = booster.predict(dtest)

    for name, pred, true in [("train", pred_train, y_train), ("test", pred_test, y_test)]:
        for thresh, label in [(0.92, "instant_drop"), (0.70, "warning")]:
            p = (pred >= thresh).astype(int)
            tp = int(np.sum((p == 1) & (true == 1)))
            fp = int(np.sum((p == 1) & (true == 0)))
            fn = int(np.sum((p == 0) & (true == 1)))
            tn = int(np.sum((p == 0) & (true == 0)))
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            rec = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
            log.info("  [%s] @ %s:  TP=%d  FP=%d  FN=%d  TN=%d  prec=%.3f  rec=%.3f  F1=%.3f",
                     name, label, tp, fp, fn, tn, prec, rec, f1)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(MODEL_OUT))
    log.info("Model saved to %s", MODEL_OUT)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Tier 1 XGBoost on CSIC 2010")
    parser.add_argument("--limit", "-n", type=int, default=0, help="Sample limit (0 = all)")
    parser.add_argument("--test-split", type=float, default=0.2, help="Test split ratio")
    args = parser.parse_args()
    main(limit=args.limit, test_split=args.test_split)
