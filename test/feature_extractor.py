from __future__ import annotations

import math
import re
import time
from collections import defaultdict
from typing import Any

import numpy as np

_last_seen: dict[str, float] = defaultdict(float)


SQL_KEYWORDS = [
    "SELECT", "UNION", "DROP", "DELETE", "INSERT", "UPDATE",
    "EXEC", "xp_cmdshell", "OR 1=1", "OR '1'='1", "OR \"1\"=\"1",
    "--", "/*", "*/", "1=1", "' OR", "\" OR",
]

SHELL_META = re.compile(r"[;|&`$(){}<>]")

PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\)|\.\.\\\\")

ENCODED_CHARS = re.compile(r"%[0-9a-fA-F]{2}")


def extract_features(req: dict) -> np.ndarray:
    f = np.zeros(48, dtype=np.float32)

    now = time.time()

    # ── Basic request features (0-7) ──────────────────────────
    f[0] = len(req.get("raw", "")) / 4096.0
    f[1] = len(req.get("query", "")) / 1024.0
    f[2] = len(req.get("body", "")) / 4096.0

    method = req.get("method", "GET")
    f[3] = 1.0 if method == "POST" else 0.0
    f[4] = 1.0 if method in ("PUT", "PATCH", "DELETE") else 0.0

    path = req.get("path", "")
    f[5] = 1.0 if "/login" in path else 0.0
    f[6] = 1.0 if "/search" in path else 0.0
    f[7] = 1.0 if "/ping" in path or "/file" in path else 0.0

    # ── SQL injection indicators (8-17) ───────────────────────
    text = (req.get("raw", "") + " " + req.get("body", "")).upper()
    sqli_count = sum(1 for kw in SQL_KEYWORDS if kw.upper() in text)
    f[8] = min(sqli_count / 10.0, 1.0)
    f[9] = 1.0 if "'" in text else 0.0
    f[10] = 1.0 if '"' in text else 0.0
    f[11] = 1.0 if "--" in text or "/*" in text else 0.0
    f[12] = 1.0 if "OR" in text and "=" in text else 0.0
    f[13] = 1.0 if "UNION" in text else 0.0
    f[14] = 1.0 if "DROP " in text else 0.0
    f[15] = 1.0 if "EXEC" in text else 0.0
    f[16] = 1.0 if "SLEEP" in text or "WAITFOR" in text else 0.0
    f[17] = 1.0 if any(c in text for c in "'\";") else 0.0

    # ── Command injection indicators (18-27) ──────────────────
    shell_count = len(SHELL_META.findall(text))
    f[18] = min(shell_count / 5.0, 1.0)
    f[19] = 1.0 if "whoami" in text or "id" in text else 0.0
    f[20] = 1.0 if "cat " in text or "passwd" in text or "shadow" in text else 0.0
    f[21] = 1.0 if "curl" in text or "wget" in text or "nc " in text else 0.0
    f[22] = 1.0 if "/bin/" in text or "/sh" in text or "/bash" in text else 0.0
    f[23] = 1.0 if "ping" in text and any(c in text for c in ";|&`") else 0.0
    f[24] = 1.0 if "$(" in text or "`" in text else 0.0
    f[25] = 1.0 if ">" in text or ">>" in text or "2>" in text else 0.0
    f[26] = 1.0 if "127.0.0.1" in text or "localhost" in text else 0.0
    f[27] = 1.0 if "nslookup" in text or "dig " in text else 0.0

    # ── Path traversal indicators (28-34) ─────────────────────
    pt_count = len(PATH_TRAVERSAL.findall(text))
    f[28] = min(pt_count / 5.0, 1.0)
    f[29] = 1.0 if "../" in text or "..\\" in text else 0.0
    f[30] = 1.0 if "/etc/" in text or "/var/" in text else 0.0
    f[31] = 1.0 if "/passwd" in text or "/shadow" in text else 0.0
    f[32] = 1.0 if "\\\\" in text else 0.0

    enc_count = len(ENCODED_CHARS.findall(text))
    f[33] = min(enc_count / 10.0, 1.0)

    # ── XSS indicators (34-39) ────────────────────────────────
    f[34] = 1.0 if "<script" in text or "<img" in text or "<svg" in text else 0.0
    f[35] = 1.0 if "onerror" in text or "onload" in text or "onclick" in text else 0.0
    f[36] = 1.0 if "javascript:" in text or "alert(" in text else 0.0
    f[37] = 1.0 if "document.cookie" in text or "fetch(" in text else 0.0
    f[38] = 1.0 if "><" in text or '">' in text else 0.0
    f[39] = 1.0 if "&#" in text or "\\x" in text else 0.0

    # ── Rate / behavioral features (40-47) ────────────────────
    src_ip = req.get("source_ip", "0.0.0.0")
    last = _last_seen.get(src_ip, 0.0)
    delta = now - last if last else 999.0
    _last_seen[src_ip] = now
    f[40] = min(math.log(max(delta, 0.1) + 1) / 10.0, 1.0)

    unique_chars = len(set(text))
    f[41] = min(unique_chars / 96.0, 1.0)
    f[42] = min(len(text) / 4096.0, 1.0)

    num_count = sum(1 for c in text if c.isdigit())
    f[43] = min(num_count / 100.0, 1.0)
    special_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
    f[44] = min(special_count / 50.0, 1.0)
    space_count = text.count(" ")
    f[45] = min(space_count / 50.0, 1.0)

    entropy = _calc_entropy(text)
    f[46] = min(entropy / 8.0, 1.0)

    has_auth_header = 1.0 if "authorization" in req.get("headers", {}) else 0.0
    f[47] = has_auth_header

    return f


def _calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def reset_rate_tracker() -> None:
    _last_seen.clear()
