from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

log = logging.getLogger(__name__)


class LLMReasoner:
    def __init__(
        self,
        api_base: str = "http://localhost:8000/v1",
        api_key: str = "",
        model: str = "gpt-4o-mini",
        max_tokens: int = 2048,
        system_prompt: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt or (
            "You are a security analyst reviewing HTTP traffic warnings."
        )
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        self._client = httpx.AsyncClient(
            base_url=self.api_base,
            headers=headers,
            timeout=self.timeout,
        )
        log.info("LLM reasoner started (model=%s, endpoint=%s)", self.model, self.api_base)

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def analyze(self, context: dict) -> tuple[str, str]:
        if self._client is None:
            return "PASS", "LLM not initialized"

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": self._format_context(context)},
        ]

        try:
            resp = await self._client.post("/chat/completions", json={
                "model": self.model,
                "messages": messages,
                "max_tokens": self.max_tokens,
                "temperature": 0.1,
            })
            resp.raise_for_status()
            body = resp.json()
            choice = body["choices"][0]
            reply = choice["message"]["content"].strip().upper()
            log.info("LLM reply: %s", reply)
            if reply.startswith("BLOCK"):
                return "BLOCK", reply
            if reply.startswith("WARN"):
                return "WARN", reply
            return "PASS", reply
        except Exception as exc:
            log.error("LLM request failed: %s", exc)
            return "ERROR", str(exc)

    @staticmethod
    def _format_context(context: dict) -> str:
        lines = ["# Security Alert Summary", ""]
        alerts = context.get("alerts", [])
        for a in alerts:
            lines.append(
                f"- IP={a.get('source_ip', '?')} "
                f"weight={a.get('weight', 0):.3f} "
                f"tactic={a.get('tactic', '?')}"
            )
        if not alerts:
            lines.append("(no alerts)")
        lines.extend([
            "",
            f"Total accumulated weight: {context.get('total_weight', 0):.3f}",
            f"Threshold: {context.get('threshold', 10)}",
            "",
            "Respond with exactly one word: BLOCK, WARN, or PASS.",
        ])
        return "\n".join(lines)
