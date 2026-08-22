"""Network Event ORM Model."""

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, utc_now
from app.models.enums import Protocol, Severity

if TYPE_CHECKING:
    from app.models.device import Device
    from app.models.user import User


class NetworkEvent(Base, TimestampMixin):
    """Network connection or telemetry event for baseline and anomaly tracking."""

    __tablename__ = "network_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    device_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
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
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[Protocol] = mapped_column(
        Enum(Protocol, name="event_protocol_enum", native_enum=False),
        default=Protocol.TCP,
        nullable=False,
    )
    bytes_transferred: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    anomaly_reason: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="event_severity_enum", native_enum=False),
        default=Severity.INFO,
        nullable=False,
    )

    # Relationships
    device: Mapped[Optional["Device"]] = relationship("Device", back_populates="events")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="network_events")

