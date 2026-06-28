"""Brute-force login simulation."""

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

print(f"\n── Brute-force login ── target={TARGET}:{PORT}\n")

passwords = ["admin", "123456", "password", "qwerty", "letmein",
             "admin123", "root", "toor", "passw0rd", "abc123",
             "monkey", "dragon", "master", "111111", "sunshine"]

for user in ["admin", "root"]:
    for pwd in passwords:
        req("POST", "/login", {"user": user, "pass": pwd})

print("\nDone.")
