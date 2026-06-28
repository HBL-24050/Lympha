import logging
import subprocess

logger = logging.getLogger(__name__)


class Firewall:
    def __init__(self, chain: str = "LYMPHA"):
        self.chain = chain
        self._available = self._check_iptables()
        if self._available:
            self._ensure_chain()

    def _check_iptables(self):
        try:
            subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("iptables not available — blocks will be simulated")
            return False

    def _ensure_chain(self):
        result = subprocess.run(
            ["iptables", "-L", self.chain, "-n"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            subprocess.run(
                ["iptables", "-N", self.chain],
                capture_output=True,
                text=True,
                timeout=5,
            )
            subprocess.run(
                ["iptables", "-I", "INPUT", "-j", self.chain],
                capture_output=True,
                text=True,
                timeout=5,
            )

    def block_ip(self, ip: str) -> bool:
        if not self._available:
            logger.info(f"[SIMULATED] Block {ip}")
            return True
        result = subprocess.run(
            ["iptables", "-I", self.chain, "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            logger.info(f"iptables: blocked {ip}")
            return True
        logger.error(f"iptables: failed to block {ip}: {result.stderr.strip()}")
        return False

    def unblock_ip(self, ip: str) -> bool:
        if not self._available:
            return True
        result = subprocess.run(
            ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            logger.info(f"iptables: unblocked {ip}")
            return True
        return False

    def is_blocked(self, ip: str) -> bool:
        if not self._available:
            return False
        result = subprocess.run(
            ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0

    def list_blocks(self) -> str:
        if not self._available:
            return ""
        result = subprocess.run(
            ["iptables", "-L", self.chain, "-n", "-v"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout
