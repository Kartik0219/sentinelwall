"""Tests proving the firewall layer never reaches a real shell and rejects bad input.

`run_command` is monkeypatched so these run cleanly in CI without root/iptables/ufw installed.
"""
import pytest

from app.firewall.base import FirewallError
from app.firewall.mock_driver import MockFirewallDriver
from app.firewall.ufw_driver import UFWFirewallDriver

pytestmark = pytest.mark.asyncio


async def test_mock_driver_blocks_and_unblocks():
    driver = MockFirewallDriver()
    await driver.block_address("203.0.113.10")
    assert "203.0.113.10" in driver.blocked
    await driver.unblock_address("203.0.113.10")
    assert "203.0.113.10" not in driver.blocked


async def test_mock_driver_rejects_invalid_ip():
    driver = MockFirewallDriver()
    with pytest.raises(FirewallError):
        await driver.block_address("'; rm -rf / #")


async def test_ufw_driver_invokes_argv_array_without_shell(monkeypatch):
    captured = {}

    async def fake_run_command(argv):
        captured["argv"] = argv
        return ""

    monkeypatch.setattr("app.firewall.ufw_driver.run_command", fake_run_command)

    driver = UFWFirewallDriver(sudo=False)
    await driver.block_address("198.51.100.5")

    assert captured["argv"] == ["ufw", "insert", "1", "deny", "from", "198.51.100.5", "to", "any"]
    assert isinstance(captured["argv"], list)


async def test_ufw_driver_refuses_command_injection_payload(monkeypatch):
    async def fake_run_command(argv):
        pytest.fail(f"run_command should never be reached with bad input, got argv={argv!r}")

    monkeypatch.setattr("app.firewall.ufw_driver.run_command", fake_run_command)

    driver = UFWFirewallDriver(sudo=False)
    with pytest.raises(FirewallError):
        await driver.block_address("1.2.3.4; rm -rf /")
