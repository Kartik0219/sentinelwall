"""Data-access helpers wrapping the ORM for alert and containment-block bookkeeping."""
import datetime as dt

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ContainmentBlock, IngestedAlert, utcnow


async def create_alert(
    session: AsyncSession,
    *,
    resource_affected: str,
    severity: str,
    threat_type: str,
    compromised_ip: str,
) -> IngestedAlert:
    alert = IngestedAlert(
        resource_affected=resource_affected,
        severity=severity,
        threat_type=threat_type,
        compromised_ip=compromised_ip,
        action_taken="NONE",
    )
    session.add(alert)
    await session.commit()
    await session.refresh(alert)
    return alert


async def mark_alert_action(session: AsyncSession, alert_id: int, action: str) -> None:
    alert = await session.get(IngestedAlert, alert_id)
    if alert is not None:
        alert.action_taken = action
        await session.commit()


async def find_active_block(session: AsyncSession, ip: str) -> ContainmentBlock | None:
    stmt = select(ContainmentBlock).where(ContainmentBlock.ip == ip, ContainmentBlock.active.is_(True))
    return (await session.execute(stmt)).scalar_one_or_none()


async def create_block(
    session: AsyncSession, *, ip: str, ttl_seconds: int, source_alert_id: int
) -> ContainmentBlock:
    now = utcnow()
    block = ContainmentBlock(
        ip=ip,
        blocked_at=now,
        expires_at=now + dt.timedelta(seconds=ttl_seconds),
        ttl_seconds=ttl_seconds,
        source_alert_id=source_alert_id,
        active=True,
    )
    session.add(block)
    await session.commit()
    await session.refresh(block)
    return block


async def list_active_blocks(session: AsyncSession) -> list[ContainmentBlock]:
    stmt = select(ContainmentBlock).where(ContainmentBlock.active.is_(True)).order_by(ContainmentBlock.expires_at)
    return list((await session.execute(stmt)).scalars().all())


async def list_expired_blocks(session: AsyncSession) -> list[ContainmentBlock]:
    stmt = select(ContainmentBlock).where(
        ContainmentBlock.active.is_(True), ContainmentBlock.expires_at <= utcnow()
    )
    return list((await session.execute(stmt)).scalars().all())


async def deactivate_block(session: AsyncSession, block_id: int) -> None:
    block = await session.get(ContainmentBlock, block_id)
    if block is not None:
        block.active = False
        await session.commit()


async def list_recent_alerts(session: AsyncSession, limit: int = 50) -> list[IngestedAlert]:
    stmt = select(IngestedAlert).order_by(IngestedAlert.id.desc()).limit(limit)
    return list((await session.execute(stmt)).scalars().all())
