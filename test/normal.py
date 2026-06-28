"""Normal (benign) traffic — should NOT trigger any alerts."""

import sys
import urllib.request
import urllib.parse
import urllib.error

TARGET = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = sys.argv[2] if len(sys.argv) > 2 else "80"
BASE = "http://{}:{}".format(TARGET, PORT)


def req(method, path, body=None, headers=None):
    url = BASE + path
    data = urllib.parse.urlencode(body).encode() if body else None
    hdrs = headers or {}
    hdrs.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
    r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=5)
        print("  {:4s} {:35s} -> {}".format(method, path, resp.status))
    except urllib.error.HTTPError as e:
        print("  {:4s} {:35s} -> {}".format(method, path, e.code))


print("\n── Normal traffic ── target={}:{}\n".format(TARGET, PORT))

req("GET", "/")
req("GET", "/api/v2/user/profile", headers={"Authorization": "Bearer valid_token"})
req("POST", "/login", {"user": "alice", "pass": "s3cret"})
req("POST", "/api/v2/user/profile", {"email": "alice@test.com", "bio": "hello"})
req("GET", "/search?q=hello+world")
req("POST", "/exec", {"cmd": "whoami"})
req("POST", "/upload", headers={"X-Filename": "readme.txt"}, body=b"hello data")
req("GET", "/api/v2/user/profile")
req("GET", "/search?q=lympha+security")
req("POST", "/login", {"user": "bob", "pass": "password123"})

print("\nDone — no attacks sent.")
