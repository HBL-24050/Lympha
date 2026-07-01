import asyncio
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

CHAIN_NAME = "LYMPHA_BLOCK"


class IptablesManager:
    def __init__(self, control_interface: str, mode: str) -> None:
        self.interface = control_interface
        self.mode = mode

    async def _run(self, *args: str) -> tuple[str, str]:
        cmd = ["iptables"] + list(args)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout.decode().strip(), stderr.decode().strip()

    async def ensure_chain(self) -> None:
        if self.mode == "test":
            return
        out, err = await self._run("-L", CHAIN_NAME, "-n")
        if "No chain/target/match" in err or not out:
            await self._run("-N", CHAIN_NAME)
            await self._run("-I", "INPUT", "-i", self.interface, "-j", CHAIN_NAME)
            log.info("Created iptables chain %s on %s", CHAIN_NAME, self.interface)

    async def block_ip(self, ip: str, reason: str = "") -> bool:
        if self.mode == "test":
            log.info(
                "[TEST MODE] Would block %s | reason: %s",
                ip, reason or "no reason",
            )
            return False

        out, err = await self._run("-C", CHAIN_NAME, "-s", ip, "-j", "DROP")
        if not err:
            log.debug("IP %s already blocked in %s", ip, CHAIN_NAME)
            return False

        out, err = await self._run("-A", CHAIN_NAME, "-s", ip, "-j", "DROP")
        if err:
            log.error("Failed to block %s: %s", ip, err)
            return False

        log.info(
            "[BLOCKED] %s @ %s | reason: %s",
            ip, datetime.now(timezone.utc).isoformat(), reason or "no reason",
        )
        return True

    async def unblock_ip(self, ip: str) -> bool:
        if self.mode == "test":
            log.info("[TEST MODE] Would unblock %s", ip)
            return False

        out, err = await self._run("-D", CHAIN_NAME, "-s", ip, "-j", "DROP")
        if err:
            log.warning("Failed to unblock %s: %s", ip, err)
            return False
        log.info("[UNBLOCKED] %s @ %s", ip, datetime.now(timezone.utc).isoformat())
        return True

    async def flush_chain(self) -> None:
        if self.mode == "test":
            return
        await self._run("-F", CHAIN_NAME)
        log.info("Flushed chain %s", CHAIN_NAME)

    async def list_blocked(self) -> list[str]:
        out, err = await self._run("-L", CHAIN_NAME, "-n")
        if err:
            return []
        ips: list[str] = []
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] and parts[3] == "DROP":
                ips.append(parts[3])  # source IP from the rule
        return ips
