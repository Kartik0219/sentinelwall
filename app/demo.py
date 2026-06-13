"""Public-demo support: a startup seed and an unauthenticated 'simulate attack'
endpoint, both gated behind SENTINELWALL_DEMO_MODE.

Everything here drives the SAME pipeline as the real webhook (asyncio queue →
RulesEngine → firewall driver). The deployed demo runs with the 'mock' firewall
driver, so no real containment command ever executes. Sample IPs are drawn only
from RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), which are reserved and never route to a real host.
"""

from __future__ import annotations

import logging
import random

from fastapi import APIRouter, HTTPException, Request, status

from app.config import settings
from app.schemas import AzureAlert, ExtendingProperties, Severity
from app.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])

# RFC 5737 documentation IPs — reserved, non-routable, safe to display publicly.
_DEMO_IPS = (
    [f"203.0.113.{n}" for n in (12, 50, 88, 134, 201)]
    + [f"198.51.100.{n}" for n in (7, 42, 99, 173)]
    + [f"192.0.2.{n}" for n in (15, 66, 120)]
)

# (alertName, severity). The names that map to BLOCK_IP come from alert_policies.yaml;
# one non-matching entry is included so the dashboard also shows an alert that was
# evaluated but NOT contained (demonstrating the risk matrix making a decision).
_DEMO_THREATS = [
    ("Brute Force SSH Attack", Severity.HIGH),
    ("Brute Force RDP Attack", Severity.HIGH),
    ("Anomalous SSH Login Attempt", Severity.MEDIUM),
    ("Malicious IP Communication", Severity.LOW),
    ("Unusual sign-in activity", Severity.LOW),  # no policy match → evaluated, not blocked
]

_DEMO_RESOURCES = [
    ("sub-prod-01", "rg-prod-eastus"),
    ("sub-prod-01", "rg-web-frontend"),
    ("sub-corp-02", "rg-bastion-hosts"),
]


def build_sample_alert() -> AzureAlert:
    """Construct one realistic, harmless sample alert from the demo pools."""
    name, severity = random.choice(_DEMO_THREATS)
    sub, rg = random.choice(_DEMO_RESOURCES)
    return AzureAlert(
        subscriptionId=sub,
        resourceGroup=rg,
        alertName=name,
        severity=severity,
        extendingProperties=ExtendingProperties(compromised_ip=random.choice(_DEMO_IPS)),
    )


async def seed(state: AppState, count: int = 4) -> None:
    """Enqueue a few distinct-IP sample alerts so the dashboard isn't empty on first load."""
    seen: set[str] = set()
    while len(seen) < count and len(seen) < len(_DEMO_IPS):
        alert = build_sample_alert()
        ip = alert.extendingProperties.compromised_ip
        if ip in seen:
            continue
        seen.add(ip)
        await state.alert_queue.put(alert)
    logger.info(
        "demo seed enqueued sample alerts",
        extra={"component": "demo", "action": "seed", "status": "queued", "target_ip": "-"},
    )


@router.get("/status")
async def demo_status() -> dict:
    """Always available — lets the dashboard decide whether to show demo controls."""
    return {"enabled": settings.demo_mode}


@router.post("/simulate", status_code=status.HTTP_202_ACCEPTED)
async def simulate(request: Request) -> dict:
    """Enqueue one sample alert. Unauthenticated, but only works when demo mode is on."""
    if not settings.demo_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="demo mode is not enabled on this server",
        )
    state: AppState = request.app.state.sentinel
    alert = build_sample_alert()
    await state.alert_queue.put(alert)
    return {
        "queued": True,
        "alert": {
            "threat": alert.alertName,
            "severity": alert.severity.value,
            "ip": alert.extendingProperties.compromised_ip,
        },
    }
