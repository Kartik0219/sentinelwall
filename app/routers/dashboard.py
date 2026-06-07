"""JSON API backing the SOC operational dashboard (alert ticker, blocked-IP table, status)."""
import datetime as dt

from fastapi import APIRouter, Request

from app.db.repository import list_active_blocks, list_recent_alerts
from app.db.session import get_session
from app.schemas import AlertView, BlockedIPView, SystemStatus
from app.state import AppState

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/alerts", response_model=list[AlertView])
async def recent_alerts(limit: int = 50) -> list[AlertView]:
    async with get_session() as session:
        records = await list_recent_alerts(session, limit=limit)
    return [
        AlertView(
            id=r.id,
            received_at=r.received_at.isoformat(),
            resource_affected=r.resource_affected,
            severity=r.severity,
            threat_type=r.threat_type,
            compromised_ip=r.compromised_ip,
            action_taken=r.action_taken,
        )
        for r in records
    ]


@router.get("/blocks", response_model=list[BlockedIPView])
async def active_blocks() -> list[BlockedIPView]:
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    async with get_session() as session:
        blocks = await list_active_blocks(session)
    return [
        BlockedIPView(
            ip=b.ip,
            blocked_at=b.blocked_at.isoformat(),
            expires_at=b.expires_at.isoformat(),
            ttl_remaining_seconds=max(0, int((b.expires_at - now).total_seconds())),
            source_alert_id=b.source_alert_id,
        )
        for b in blocks
    ]


@router.get("/status", response_model=SystemStatus)
async def system_status(request: Request) -> SystemStatus:
    state: AppState = request.app.state.sentinel
    async with get_session() as session:
        blocks = await list_active_blocks(session)

    status_label = "Degraded" if state.degraded else ("Active" if blocks else "Safe")
    return SystemStatus(
        status=status_label,
        degraded_reason=state.degraded_reason,
        queue_depth=state.alert_queue.qsize(),
        active_blocks=len(blocks),
    )
