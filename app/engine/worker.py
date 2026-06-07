"""Background workers: the mitigation queue consumer and the TTL expiry scanner.

Concurrency notes:
  * `mitigation_worker` pulls alerts off the asyncio.Queue sequentially — the queue itself
    serializes processing, so there is no parallel consumption to race on.
  * The remaining race is between (a) duplicate/concurrent alerts for the same IP arriving
    in quick succession and (b) the expiry scanner unblocking that same IP concurrently.
    `state.mitigation_lock` (an asyncio.Lock) wraps the read-check-act sequence — checking
    for an existing active block, calling the firewall driver, and writing the new block row —
    so two coroutines can never both decide to issue a duplicate `block_address` call.
"""
import asyncio
import logging

from app.db.repository import (
    create_alert,
    create_block,
    deactivate_block,
    find_active_block,
    list_expired_blocks,
    mark_alert_action,
)
from app.db.session import get_session
from app.firewall.base import FirewallError
from app.schemas import AzureAlert
from app.state import AppState

logger = logging.getLogger(__name__)


async def _apply_decision(state: AppState, alert_id: int, ip: str, action: str, ttl_seconds: int) -> None:
    if action != "BLOCK_IP":
        return

    async with state.mitigation_lock:
        async with get_session() as session:
            existing = await find_active_block(session, ip)
            if existing is not None:
                logger.info(
                    "duplicate alert suppressed - IP already under active containment",
                    extra={"component": "engine.worker", "action": "dedupe", "status": "skipped", "target_ip": ip},
                )
                await mark_alert_action(session, alert_id, "DEDUPED_ALREADY_BLOCKED")
                return

            try:
                await state.firewall.block_address(ip)
            except FirewallError:
                logger.exception(
                    "firewall driver failed to block address",
                    extra={"component": "engine.worker", "action": "block", "status": "failed", "target_ip": ip},
                )
                state.mark_degraded(f"firewall block failed for {ip}")
                await mark_alert_action(session, alert_id, "BLOCK_FAILED")
                return

            await create_block(session, ip=ip, ttl_seconds=ttl_seconds, source_alert_id=alert_id)
            await mark_alert_action(session, alert_id, "BLOCKED")
            state.clear_degraded()


async def mitigation_worker(state: AppState) -> None:
    """Consumes AzureAlert objects from the queue, scores them, and triggers containment."""
    while True:
        alert = await state.alert_queue.get()
        try:
            decision = state.rules_engine.evaluate(alert.alertName, alert.severity)
            ip = alert.extendingProperties.compromised_ip

            async with get_session() as session:
                record = await create_alert(
                    session,
                    resource_affected=f"{alert.subscriptionId}/{alert.resourceGroup}",
                    severity=alert.severity.value,
                    threat_type=alert.alertName,
                    compromised_ip=ip,
                )

            logger.info(
                "alert evaluated",
                extra={
                    "component": "engine.worker",
                    "action": "evaluate",
                    "status": decision.action,
                    "target_ip": ip,
                },
            )

            await _apply_decision(state, record.id, ip, decision.action, decision.ttl_seconds)
        except Exception:
            logger.exception(
                "unexpected error processing alert from queue",
                extra={"component": "engine.worker", "action": "process", "status": "error", "target_ip": "-"},
            )
            state.mark_degraded("unexpected exception in mitigation worker")
        finally:
            state.alert_queue.task_done()


async def expiry_scanner(state: AppState, interval_seconds: int = 30) -> None:
    """Polls the SQLite store every `interval_seconds` and lifts blocks whose TTL has elapsed."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            async with get_session() as session:
                expired = await list_expired_blocks(session)

            for block in expired:
                async with state.mitigation_lock:
                    try:
                        await state.firewall.unblock_address(block.ip)
                    except FirewallError:
                        logger.exception(
                            "firewall driver failed to unblock expired address",
                            extra={
                                "component": "engine.expiry_scanner",
                                "action": "unblock",
                                "status": "failed",
                                "target_ip": block.ip,
                            },
                        )
                        state.mark_degraded(f"firewall unblock failed for {block.ip}")
                        continue

                    async with get_session() as session:
                        await deactivate_block(session, block.id)

                    logger.info(
                        "expired containment lifted",
                        extra={
                            "component": "engine.expiry_scanner",
                            "action": "unblock",
                            "status": "success",
                            "target_ip": block.ip,
                        },
                    )
        except Exception:
            logger.exception(
                "unexpected error during expiry scan",
                extra={"component": "engine.expiry_scanner", "action": "scan", "status": "error", "target_ip": "-"},
            )
            state.mark_degraded("unexpected exception in expiry scanner")
