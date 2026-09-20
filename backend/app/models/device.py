"""Device ORM Model."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    JSON,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, utc_now
from app.models.enums import DeviceType


if TYPE_CHECKING:
    from app.models.network_event import NetworkEvent
    from app.models.open_port import OpenPort
    from app.models.risk_assessment import RiskAssessment
    from app.models.security_finding import SecurityFinding
    from app.models.user import User


class Device(Base, TimestampMixin):
    """
    Network device profile discovered or enrolled
    on an authorized private subnet.
    """

    __tablename__ = "devices"

    # ============================================================
    # PRIMARY KEY
    # ============================================================

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ============================================================
    # RESOURCE OWNERSHIP
    # ============================================================

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )

    # ============================================================
    # NETWORK INFORMATION
    # ============================================================

    ip_address: Mapped[str] = mapped_column(
        String(45),
        index=True,
        nullable=False,
    )

    mac_address: Mapped[str] = mapped_column(
        String(17),
        index=True,
        nullable=False,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        default="",
        nullable=False,
    )

    custom_name: Mapped[str] = mapped_column(
        String(255),
        default="",
        nullable=False,
    )

    # ============================================================
    # DEVICE CLASSIFICATION
    # ============================================================

    vendor: Mapped[str] = mapped_column(
        String(255),
        default="Unknown Vendor",
        nullable=False,
    )

    vendor_source: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    device_role: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    identity_confidence: Mapped[str] = mapped_column(String(20), default="LOW", nullable=False)
    identity_evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    device_type: Mapped[DeviceType] = mapped_column(
        Enum(
            DeviceType,
            name="device_type_enum",
            native_enum=False,
        ),
        default=DeviceType.UNKNOWN,
        nullable=False,
    )

    # ============================================================
    # TRUST / AVAILABILITY
    # ============================================================

    is_trusted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    is_online: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # ============================================================
    # RISK
    # ============================================================

    risk_score: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    # ============================================================
    # DISCOVERY TIMESTAMPS
    # ============================================================

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # ============================================================
    # USER RELATIONSHIP
    # ============================================================

    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="devices",
    )

    # ============================================================
    # OPEN PORTS
    # ============================================================

    ports: Mapped[List["OpenPort"]] = relationship(
        "OpenPort",
        back_populates="device",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    # ============================================================
    # SECURITY FINDINGS
    # ============================================================

    findings: Mapped[List["SecurityFinding"]] = relationship(
        "SecurityFinding",
        back_populates="device",
        cascade="all, delete-orphan",
    )

    # ============================================================
    # NETWORK EVENTS
    # ============================================================

    events: Mapped[List["NetworkEvent"]] = relationship(
        "NetworkEvent",
        back_populates="device",
        cascade="all, delete-orphan",
    )

    # ============================================================
    # RISK ASSESSMENTS
    # ============================================================

    risk_assessments: Mapped[List["RiskAssessment"]] = relationship(
        "RiskAssessment",
        back_populates="device",
        cascade="all, delete-orphan",
    )
