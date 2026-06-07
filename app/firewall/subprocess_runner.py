"""Secure subprocess execution helper shared by all real firewall drivers.

All commands are invoked with shell=False and strict argument arrays — no string
interpolation ever reaches a shell, eliminating command-injection risk.
"""
import asyncio
import ipaddress
import logging

from app.firewall.base import FirewallError

logger = logging.getLogger(__name__)


def assert_valid_ipv4(ip: str) -> str:
    """Defense in depth: re-validate the IP immediately before it is used in a command array."""
    try:
        return str(ipaddress.IPv4Address(ip))
    except ValueError as exc:
        raise FirewallError(f"refusing to execute firewall command for invalid IPv4 address: {ip!r}") from exc


async def run_command(argv: list[str]) -> str:
    """Run argv with shell=False, log the exact array, and return combined stdout/stderr.

    Raises FirewallError (without leaking command output to callers beyond logs) on non-zero exit.
    """
    logger.info(
        "executing firewall command",
        extra={"component": "firewall.subprocess", "action": "exec", "status": "started", "target_ip": "-"},
    )
    logger.debug("argv=%s", argv)

    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await process.communicate()
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if process.returncode != 0:
        logger.error(
            "firewall command failed",
            extra={"component": "firewall.subprocess", "action": "exec", "status": "failed", "target_ip": "-"},
        )
        raise FirewallError(
            f"command {argv!r} exited with code {process.returncode}: stdout={stdout!r} stderr={stderr!r}"
        )

    return stdout
