"""User ORM Model."""

import uuid
from typing import List, TYPE_CHECKING
from sqlalchemy import Boolean, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.scan_job import ScanJob
    from app.models.device import Device
    from app.models.risk_assessment import RiskAssessment
    from app.models.network_event import NetworkEvent


class User(Base, TimestampMixin):
    """User account for home network security administration."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorized_network_scope: Mapped[str] = mapped_column(
        String(100),
        default="192.168.1.0/24",
        nullable=False,
    )

    # Resource Relationships
    scans: Mapped[List["ScanJob"]] = relationship(
        "ScanJob",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    devices: Mapped[List["Device"]] = relationship(
        "Device",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    risk_assessments: Mapped[List["RiskAssessment"]] = relationship(
        "RiskAssessment",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    network_events: Mapped[List["NetworkEvent"]] = relationship(
        "NetworkEvent",
        back_populates="user",
        cascade="all, delete-orphan",
    )

