"""Selects the appropriate firewall driver implementation based on configuration."""
from app.firewall.base import BaseFirewallDriver
from app.firewall.mock_driver import MockFirewallDriver
from app.firewall.ufw_driver import IPTablesFirewallDriver, UFWFirewallDriver


def build_firewall_driver(driver_name: str) -> BaseFirewallDriver:
    normalized = driver_name.strip().lower()
    if normalized == "mock":
        return MockFirewallDriver()
    if normalized == "ufw":
        return UFWFirewallDriver()
    if normalized == "iptables":
        return IPTablesFirewallDriver()
    raise ValueError(f"unknown firewall driver: {driver_name!r} (expected mock|ufw|iptables)")
