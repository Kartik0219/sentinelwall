"""Centralized runtime configuration loaded from environment variables."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    webhook_token: str
    db_path: str
    firewall_driver: str
    policies_path: str
    expiry_scan_interval_seconds: int = 30
    demo_mode: bool = False


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> Settings:
    return Settings(
        webhook_token=os.environ.get("SENTINELWALL_WEBHOOK_TOKEN", ""),
        db_path=os.environ.get("SENTINELWALL_DB_PATH", "sentinelwall.db"),
        firewall_driver=os.environ.get("SENTINELWALL_FIREWALL_DRIVER", "mock"),
        policies_path=os.environ.get("SENTINELWALL_POLICIES_PATH", "alert_policies.yaml"),
        demo_mode=_truthy(os.environ.get("SENTINELWALL_DEMO_MODE", "")),
    )


settings = load_settings()
