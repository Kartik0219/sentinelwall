"""Abstract contract for host/network-level firewall mitigation drivers."""
from abc import ABC, abstractmethod


class FirewallError(Exception):
    """Raised when a firewall driver fails to apply or remove a containment rule."""


class BaseFirewallDriver(ABC):
    @abstractmethod
    async def block_address(self, ip: str) -> None:
        """Apply a deny rule for the given IPv4 address. Must raise FirewallError on failure."""

    @abstractmethod
    async def unblock_address(self, ip: str) -> None:
        """Remove a previously applied deny rule for the given IPv4 address."""
