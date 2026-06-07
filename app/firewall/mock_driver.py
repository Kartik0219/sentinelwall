"""In-memory firewall driver used for local development, demos, and CI test runs."""
import logging

from app.firewall.base import BaseFirewallDriver
from app.firewall.subprocess_runner import assert_valid_ipv4

logger = logging.getLogger(__name__)


class MockFirewallDriver(BaseFirewallDriver):
    """Records block/unblock calls without touching the host OS — safe for CI runners without root."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    async def block_address(self, ip: str) -> None:
        clean_ip = assert_valid_ipv4(ip)
        self.blocked.add(clean_ip)
        logger.info(
            "mock firewall block",
            extra={"component": "firewall.mock", "action": "block", "status": "success", "target_ip": clean_ip},
        )

    async def unblock_address(self, ip: str) -> None:
        clean_ip = assert_valid_ipv4(ip)
        self.blocked.discard(clean_ip)
        logger.info(
            "mock firewall unblock",
            extra={"component": "firewall.mock", "action": "unblock", "status": "success", "target_ip": clean_ip},
        )
