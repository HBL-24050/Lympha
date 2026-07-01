from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger(__name__)

REQUEST_LOG: list[dict] = []


class VulnerableHTTPProtocol(asyncio.Protocol):
    def __init__(
        self,
        on_request: Callable[[dict], None] | None = None,
        log_file: str | None = None,
    ) -> None:
        self.transport: asyncio.Transport | None = None
        self._buffer = b""
        self._on_request = on_request
        self._log_file = log_file
        self._remote_addr = "0.0.0.0"

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport
        sock = transport.get_extra_info("peername")
        self._remote_addr = f"{sock[0]}:{sock[1]}" if sock else "unknown"

    def _write_log(self, record: dict) -> None:
        if not self._log_file:
            return
        import json, os
        os.makedirs(os.path.dirname(self._log_file) or ".", exist_ok=True)
        with open(self._log_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        if b"\r\n\r\n" in self._buffer:
            self._handle_request()

    def _handle_request(self) -> None:
        raw = self._buffer.decode("utf-8", errors="replace")
        head, _, body = raw.partition("\r\n\r\n")
        lines = head.split("\r\n")
        if not lines:
            return

        method, path, _ = lines[0].split(" ", 2) if " " in lines[0] else ("GET", "/", "")
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self._remote_addr.split(":")[0],
            "method": method,
            "path": path,
            "query": query,
            "body": body.strip(),
            "headers": headers,
            "raw": raw[:2048],
        }

        status, resp_body = self._route(record)
        resp = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(resp_body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{resp_body}"
        )
        if self.transport:
            self.transport.write(resp.encode())
            self.transport.close()

        REQUEST_LOG.append(record)
        if self._on_request:
            self._on_request(record)
        self._write_log(record)

    def _route(self, req: dict) -> tuple[str, str]:
        path = req["path"]
        if path == "/":
            return "200 OK", "Welcome to Lympha test server"
        if path == "/login":
            return self._login(req)
        if path == "/search":
            return "200 OK", f"Search results for: {req.get('query', '')}"
        if path == "/ping":
            return self._ping(req)
        if path == "/file":
            return self._file(req)
        return "404 Not Found", "Not Found"

    def _login(self, req: dict) -> tuple[str, str]:
        body = req.get("body", "{}")
        try:
            data = json.loads(body)
            user = data.get("user", "")
            password = data.get("pass", "")
        except json.JSONDecodeError:
            user = body
            password = ""
        log.info("Login attempt: user=%s pass=%s from %s", user, password, req["source_ip"])
        if "' OR '1'='1" in user or "' OR '1'='1" in password:
            return "200 OK", "Logged in as admin (vulnerable)"
        return "401 Unauthorized", "Invalid credentials"

    def _ping(self, req: dict) -> tuple[str, str]:
        host = req.get("query", "").replace("host=", "")
        if not host:
            return "400 Bad Request", "Missing host"
        import subprocess
        try:
            result = subprocess.run(
                ["ping", "-c", "1", host],
                capture_output=True, text=True, timeout=5,
            )
            return "200 OK", result.stdout or result.stderr
        except Exception as e:
            return "500 Error", str(e)

    def _file(self, req: dict) -> tuple[str, str]:
        name = req.get("query", "").replace("name=", "")
        if not name:
            return "400 Bad Request", "Missing name"
        import os
        base = os.path.abspath("/etc")
        target = os.path.abspath(os.path.join(base, name))
        if not target.startswith(base):
            return "200 OK", f"Path traversal detected, but here's the file: {open(target).read()[:512]}"
        try:
            content = open(target).read()[:512]
            return "200 OK", content
        except Exception as e:
            return "404 Not Found", str(e)


class VulnServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        on_request: Callable[[dict], None] | None = None,
        log_file: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self._on_request = on_request
        self._log_file = log_file
        self._server: asyncio.AbstractServer | None = None

    def _write_log(self, record: dict) -> None:
        if not self._log_file:
            return
        import json, os
        os.makedirs(os.path.dirname(self._log_file) or ".", exist_ok=True)
        with open(self._log_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        factory = lambda: VulnerableHTTPProtocol(
            on_request=self._on_request,
            log_file=self._log_file,
        )
        self._server = await loop.create_server(factory, self.host, self.port)
        log.info("Vulnerable server listening on %s:%s", self.host, self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            log.info("Vulnerable server stopped")

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


def main() -> None:
    import sys
    args = sys.argv[1:]
    port = 8080
    log_file = None

    for i, a in enumerate(args):
        if a == "--log" and i + 1 < len(args):
            log_file = args[i + 1]
        elif a.isdigit():
            port = int(a)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    async def run() -> None:
        server = VulnServer(host="127.0.0.1", port=port, log_file=log_file)
        await server.start()
        print(f"Vulnerable server listening on {server.url}")
        if log_file:
            print(f"  Logging requests to {log_file}")
        try:
            while True:
                await asyncio.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            await server.stop()

    asyncio.run(run())


if __name__ == "__main__":
    main()
