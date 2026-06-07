"""SQLAlchemy ORM models for persistent SOAR state tracking."""
import datetime as dt

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    """Naive UTC timestamp — SQLite drops tzinfo on round-trip, so we stay naive throughout."""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class IngestedAlert(Base):
    __tablename__ = "ingested_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    resource_affected: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    threat_type: Mapped[str] = mapped_column(String(512), nullable=False)
    compromised_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    action_taken: Mapped[str] = mapped_column(String(64), nullable=False, default="NONE")

    blocks: Mapped[list["ContainmentBlock"]] = relationship(back_populates="source_alert")


class ContainmentBlock(Base):
    __tablename__ = "containment_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    blocked_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    source_alert_id: Mapped[int] = mapped_column(ForeignKey("ingested_alerts.id"), nullable=False)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)

    source_alert: Mapped["IngestedAlert"] = relationship(back_populates="blocks")
