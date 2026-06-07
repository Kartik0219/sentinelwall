"""Tests for the webhook ingestion endpoint: auth, validation, and end-to-end containment."""
import asyncio

import pytest

pytestmark = pytest.mark.asyncio


def _payload(alert_name="Brute Force SSH Attack", severity="High", ip="203.0.113.50"):
    return {
        "subscriptionId": "sub-1234",
        "resourceGroup": "rg-prod-eastus",
        "alertName": alert_name,
        "severity": severity,
        "extendingProperties": {"compromised_ip": ip},
    }


async def test_rejects_missing_token(client):
    resp = await client.post("/api/v1/alerts/azure", json=_payload())
    assert resp.status_code == 401


async def test_rejects_wrong_token(client):
    resp = await client.post(
        "/api/v1/alerts/azure", json=_payload(), headers={"X-Webhook-Token": "wrong"}
    )
    assert resp.status_code == 401


async def test_rejects_invalid_ip(client, auth_headers):
    resp = await client.post(
        "/api/v1/alerts/azure", json=_payload(ip="not-an-ip"), headers=auth_headers
    )
    assert resp.status_code == 422


async def test_accepts_valid_alert_and_queues_it(client, auth_headers, app_with_state):
    _app, state = app_with_state
    resp = await client.post("/api/v1/alerts/azure", json=_payload(), headers=auth_headers)
    assert resp.status_code == 202
    assert resp.json()["queued"] is True


async def test_high_severity_brute_force_triggers_block(client, auth_headers, app_with_state):
    _app, state = app_with_state
    ip = "198.51.100.77"
    resp = await client.post("/api/v1/alerts/azure", json=_payload(ip=ip), headers=auth_headers)
    assert resp.status_code == 202

    for _ in range(50):
        await asyncio.sleep(0.05)
        blocks = (await client.get("/api/v1/dashboard/blocks")).json()
        if any(b["ip"] == ip for b in blocks):
            break
    else:
        pytest.fail("expected IP to be blocked within timeout")

    assert ip in state.firewall.blocked


async def test_low_severity_alert_does_not_trigger_block(client, auth_headers, app_with_state):
    _app, state = app_with_state
    ip = "198.51.100.200"
    resp = await client.post(
        "/api/v1/alerts/azure",
        json=_payload(alert_name="Unusual sign-in activity", severity="Low", ip=ip),
        headers=auth_headers,
    )
    assert resp.status_code == 202

    await asyncio.sleep(0.5)
    assert ip not in state.firewall.blocked
