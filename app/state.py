"""Process-wide shared state: queue, locks, firewall driver, degraded-mode flag."""
import asyncio
from dataclasses import dataclass, field

from app.engine.rules import RulesEngine
from app.firewall.base import BaseFirewallDriver
from app.schemas import AzureAlert


@dataclass
class AppState:
    alert_queue: asyncio.Queue[AzureAlert]
    rules_engine: RulesEngine
    firewall: BaseFirewallDriver
    mitigation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    degraded: bool = False
    degraded_reason: str | None = None

    def mark_degraded(self, reason: str) -> None:
        self.degraded = True
        self.degraded_reason = reason

    def clear_degraded(self) -> None:
        self.degraded = False
        self.degraded_reason = None
