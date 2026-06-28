"""
Vulnerable HTTP server for testing Lympha detection.

Endpoints:
  GET  /                                       info page
  POST /login                                  login (simulates brute-force target)
  GET  /api/v2/user/profile                    fetch profile
  POST /api/v2/user/profile                    update profile
  GET  /search?q=<query>                       search (SQLi simulation)
  POST /exec                                   command injection
  POST /upload                                 file upload simulation

Run:  sudo python3 test/vuln_server.py [port]
"""

import json
import os
import socketserver
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80


class Handler(BaseHTTPRequestHandler):

    def _json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _html(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def _text(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        print(f"  >>> {args[0]} {args[1]} {args[2]}")

    # -- Routes -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        if path == "" or path == "/":
            return self._index()

        if path == "/api/v2/user/profile":
            return self._profile()

        if path == "/search":
            return self._search(qs)

        self._json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""

        if self.path == "/login":
            return self._login(body)
        if self.path == "/api/v2/user/profile":
            return self._profile_update(body)
        if self.path == "/exec":
            return self._exec(body)
        if self.path == "/upload":
            return self._upload(body)

        self._json({"error": "not found"}, 404)

    # -- Handlers ---------------------------------------------------------

    def _index(self):
        self._html("""<!DOCTYPE html>
<html><body>
<h1>Lympha Test Server</h1>
<p>Endpoints:</p>
<ul>
  <li>POST /login        — login form</li>
  <li>GET /api/v2/user/profile — user profile</li>
  <li>POST /api/v2/user/profile — update profile</li>
  <li>GET /search?q=...  — search (try: ?q=1' OR '1'='1)</li>
  <li>POST /exec         — ping (try: cmd=; ls -la)</li>
  <li>POST /upload       — file upload</li>
</ul>
</body></html>""")

    def _login(self, body):
        params = parse_qs(body)
        user = params.get("user", [""])[0]
        pwd = params.get("pass", [""])[0]
        print(f"  [!] LOGIN attempt  user={user!r}  pass={pwd!r}")
        self._json({"status": "failed", "user": user})

    def _profile(self):
        auth = self.headers.get("Authorization", "")
        print(f"  [!] PROFILE fetch   auth={auth[:40]}")
        self._json({
            "user": "admin",
            "email": "admin@lympha.test",
            "roles": ["admin", "operator"],
        })

    def _profile_update(self, body):
        params = parse_qs(body)
        email = params.get("email", [""])[0]
        bio = params.get("bio", [""])[0]
        print(f"  [!] PROFILE update  email={email!r}  bio={bio!r}")
        self._json({"status": "updated"})

    def _search(self, qs):
        q = qs.get("q", [""])[0]
        print(f"  [!] SEARCH          q={q!r}")
        if q:
            # Echo back for demo — real app would query a DB
            results = [
                {"id": 1, "title": f"Result for {q}", "snippet": q}
            ]
            self._json({"results": results})
        else:
            self._json({"results": []})

    def _exec(self, body):
        params = parse_qs(body)
        cmd = params.get("cmd", ["whoami"])[0]
        print(f"  [!] EXEC            cmd={cmd!r}")
        try:
            import subprocess
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                           timeout=5)
            self._text(out.decode())
        except Exception as e:
            self._text(f"error: {e}")

    def _upload(self, body):
        filename = self.headers.get("X-Filename", "unknown")
        size = len(body)
        print(f"  [!] UPLOAD          file={filename!r}  size={size}")
        self._json({"status": "uploaded", "file": filename, "size": size})


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = "0.0.0.0"
    print(f"Lympha test server listening on http://{host}:{PORT}")
    print(f"  Lympha sniffs port {PORT} (set via LYMPHA_HTTP_PORTS in lympha.conf)")
    print(f"  Attack: python3 test/attack.py localhost {PORT}\n")

    socketserver.TCPServer.allow_reuse_address = True
    httpd = HTTPServer((host, PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
