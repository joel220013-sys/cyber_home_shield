"""Scan Job ORM Model."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, utc_now
from app.models.enums import ScanStatus, ScanType


class ScanJob(Base, TimestampMixin):
    """Record of an authorized defensive discovery or audit scan."""

    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_subnet: Mapped[str] = mapped_column(String(100), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(
        Enum(ScanType, name="scan_type_enum", native_enum=False),
        default=ScanType.DISCOVERY,
        nullable=False,
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status_enum", native_enum=False),
        default=ScanStatus.PENDING,
        nullable=False,
    )
    devices_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ports_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    summary_findings: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str] = mapped_column(String(500), default="", nullable=False)

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="scans")

