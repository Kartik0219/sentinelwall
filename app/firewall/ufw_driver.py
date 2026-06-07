"""Linux UFW-backed firewall driver using array-based subprocess invocation."""
import logging

from app.firewall.base import BaseFirewallDriver, FirewallError
from app.firewall.subprocess_runner import assert_valid_ipv4, run_command

logger = logging.getLogger(__name__)


class UFWFirewallDriver(BaseFirewallDriver):
    """Drives `ufw` via `sudo` with strict argv arrays — never via a shell string."""

    def __init__(self, sudo: bool = True) -> None:
        self._prefix = ["sudo", "ufw"] if sudo else ["ufw"]

    async def block_address(self, ip: str) -> None:
        clean_ip = assert_valid_ipv4(ip)
        argv = [*self._prefix, "insert", "1", "deny", "from", clean_ip, "to", "any"]
        logger.info(
            "blocking external IP via ufw",
            extra={"component": "firewall.ufw", "action": "block", "status": "executing", "target_ip": clean_ip},
        )
        try:
            await run_command(argv)
        except FirewallError:
            logger.error(
                "ufw block failed",
                extra={"component": "firewall.ufw", "action": "block", "status": "failed", "target_ip": clean_ip},
            )
            raise
        logger.info(
            "ufw block applied",
            extra={"component": "firewall.ufw", "action": "block", "status": "success", "target_ip": clean_ip},
        )

    async def unblock_address(self, ip: str) -> None:
        clean_ip = assert_valid_ipv4(ip)
        argv = [*self._prefix, "delete", "deny", "from", clean_ip, "to", "any"]
        logger.info(
            "unblocking external IP via ufw",
            extra={"component": "firewall.ufw", "action": "unblock", "status": "executing", "target_ip": clean_ip},
        )
        try:
            await run_command(argv)
        except FirewallError:
            logger.error(
                "ufw unblock failed",
                extra={"component": "firewall.ufw", "action": "unblock", "status": "failed", "target_ip": clean_ip},
            )
            raise
        logger.info(
            "ufw block removed",
            extra={"component": "firewall.ufw", "action": "unblock", "status": "success", "target_ip": clean_ip},
        )


class IPTablesFirewallDriver(BaseFirewallDriver):
    """Drives raw `iptables` via `sudo` with strict argv arrays."""

    def __init__(self, sudo: bool = True, chain: str = "INPUT") -> None:
        self._prefix = ["sudo", "iptables"] if sudo else ["iptables"]
        self._chain = chain

    async def block_address(self, ip: str) -> None:
        clean_ip = assert_valid_ipv4(ip)
        argv = [*self._prefix, "-I", self._chain, "1", "-s", clean_ip, "-j", "DROP"]
        logger.info(
            "blocking external IP via iptables",
            extra={"component": "firewall.iptables", "action": "block", "status": "executing", "target_ip": clean_ip},
        )
        try:
            await run_command(argv)
        except FirewallError:
            logger.error(
                "iptables block failed",
                extra={"component": "firewall.iptables", "action": "block", "status": "failed", "target_ip": clean_ip},
            )
            raise
        logger.info(
            "iptables block applied",
            extra={"component": "firewall.iptables", "action": "block", "status": "success", "target_ip": clean_ip},
        )

    async def unblock_address(self, ip: str) -> None:
        clean_ip = assert_valid_ipv4(ip)
        argv = [*self._prefix, "-D", self._chain, "-s", clean_ip, "-j", "DROP"]
        logger.info(
            "unblocking external IP via iptables",
            extra={"component": "firewall.iptables", "action": "unblock", "status": "executing", "target_ip": clean_ip},
        )
        try:
            await run_command(argv)
        except FirewallError:
            logger.error(
                "iptables unblock failed",
                extra={"component": "firewall.iptables", "action": "unblock", "status": "failed", "target_ip": clean_ip},
            )
            raise
        logger.info(
            "iptables block removed",
            extra={"component": "firewall.iptables", "action": "unblock", "status": "success", "target_ip": clean_ip},
        )
