"""Tests for the demo endpoints — focus on the security gate (simulate must be
forbidden unless demo mode is explicitly enabled). The test env does not set
SENTINELWALL_DEMO_MODE, so demo mode is off here."""

import pytest


@pytest.mark.asyncio
async def test_demo_status_reports_disabled_by_default(client):
    resp = await client.get("/api/v1/demo/status")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_simulate_is_forbidden_when_demo_disabled(client):
    resp = await client.post("/api/v1/demo/simulate")
    assert resp.status_code == 403


def test_build_sample_alert_uses_reserved_ip_and_valid_severity():
    # Pure unit check — no client/db needed. Sample IPs must be RFC 5737 reserved.
    from app.demo import build_sample_alert

    reserved_prefixes = ("203.0.113.", "198.51.100.", "192.0.2.")
    for _ in range(20):
        alert = build_sample_alert()
        ip = alert.extendingProperties.compromised_ip
        assert ip.startswith(reserved_prefixes), f"non-reserved demo IP: {ip}"
        assert alert.severity.value in ("Low", "Medium", "High")
