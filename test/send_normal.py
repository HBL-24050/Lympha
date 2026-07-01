import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test.attack import benign_requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
DELAY = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5

print(f"Sending normal traffic to {TARGET} (delay={DELAY}s) — Ctrl+C to stop", flush=True)

try:
    while True:
        for req in benign_requests(1):
            full = f"{TARGET}{req['path']}"
            if req.get("query"):
                q = req["query"]
                if "=" in q:
                    k, v = q.split("=", 1)
                    full = f"{full}?{k}={urllib.parse.quote(v, safe='')}"
                else:
                    full = f"{full}?{urllib.parse.quote(q, safe='')}"
            data = req["body"].encode() if req.get("body") else None
            try:
                r = urllib.request.urlopen(
                    urllib.request.Request(full, data=data, headers={"User-Agent": "Mozilla/5.0"}),
                    timeout=3,
                )
                print(f"  {req['method']} {req['path']} -> {r.status}", flush=True)
            except urllib.error.HTTPError as e:
                print(f"  {req['method']} {req['path']} -> {e.code} {e.reason}", flush=True)
            except Exception as e:
                print(f"  {req['method']} {req['path']} -> ERR: {e}", flush=True)
            time.sleep(DELAY)
except KeyboardInterrupt:
    print("\nStopped.", flush=True)
