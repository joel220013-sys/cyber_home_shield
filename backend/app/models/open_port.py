"""Open Port ORM Model."""

import uuid
from typing import Optional
from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin
from app.models.enums import Protocol


class OpenPort(Base, TimestampMixin):
    """Network port and service discovered during authorized defensive audit."""

    __tablename__ = "open_ports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[Protocol] = mapped_column(
        Enum(Protocol, name="protocol_enum", native_enum=False),
        default=Protocol.TCP,
        nullable=False,
    )
    service_name: Mapped[str] = mapped_column(String(100), default="unknown", nullable=False)
    banner: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_risky: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_reason: Mapped[str] = mapped_column(String(255), default="", nullable=False)

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="ports")

