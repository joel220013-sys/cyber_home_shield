"""Honeypot Event Model (Isolated Deception System).

Event abstraction for capturing safe deception telemetry, probe interactions,
and defensive anomaly evidence without storing any sensitive user or attacker credentials.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING
from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, utc_now
from app.models.enums import Protocol, Severity

if TYPE_CHECKING:
    from app.models.user import User


class HoneypotEvent(Base, TimestampMixin):
    """Event abstraction for captured honeypot deception telemetry."""

    __tablename__ = "honeypot_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )
    honeypot_id: Mapped[str] = mapped_column(String(100), default="iot_gateway", nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[Protocol] = mapped_column(
        Enum(Protocol, name="honeypot_protocol_enum", native_enum=False),
        default=Protocol.TCP,
        nullable=False,
    )
    interaction_type: Mapped[str] = mapped_column(String(100), default="http_request", nullable=False)
    endpoint: Mapped[Optional[str]] = mapped_column(String(255), default="", nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), default="", nullable=True)
    payload_sample: Mapped[str] = mapped_column(Text, default="", nullable=False)
    metadata_fields: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="honeypot_severity_enum", native_enum=False),
        default=Severity.LOW,
        nullable=False,
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User")

