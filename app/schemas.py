"""Pydantic v2 schemas for inbound cloud alert payloads and internal models."""
import ipaddress
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


def severity_at_least(actual: Severity, minimum: Severity) -> bool:
    return _SEVERITY_RANK[actual] >= _SEVERITY_RANK[minimum]


class ExtendingProperties(BaseModel):
    compromised_ip: str = Field(..., description="External IPv4 address flagged by the cloud detector")

    @field_validator("compromised_ip")
    @classmethod
    def validate_ipv4(cls, value: str) -> str:
        try:
            ipaddress.IPv4Address(value)
        except ValueError as exc:
            raise ValueError(f"compromised_ip must be a valid IPv4 address, got: {value!r}") from exc
        return value


class AzureAlert(BaseModel):
    """Mirrors a (simplified) Microsoft Defender for Cloud / Azure Monitor alert payload."""

    model_config = {"str_max_length": 4096}

    subscriptionId: str = Field(..., min_length=1, max_length=128)
    resourceGroup: str = Field(..., min_length=1, max_length=256)
    alertName: str = Field(..., min_length=1, max_length=512)
    severity: Severity
    extendingProperties: ExtendingProperties

    @field_validator("subscriptionId", "resourceGroup", "alertName")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(ord(ch) < 0x20 for ch in value):
            raise ValueError("field must not contain control characters")
        return value


class AlertIngestResponse(BaseModel):
    queued: bool
    message: str


class BlockedIPView(BaseModel):
    ip: str
    blocked_at: str
    expires_at: str
    ttl_remaining_seconds: int
    source_alert_id: int


class AlertView(BaseModel):
    id: int
    received_at: str
    resource_affected: str
    severity: str
    threat_type: str
    compromised_ip: str
    action_taken: str


class SystemStatus(BaseModel):
    status: str
    degraded_reason: str | None = None
    queue_depth: int
    active_blocks: int
