"""Risk Assessment ORM Model."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING
from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base, TimestampMixin, utc_now

if TYPE_CHECKING:
    from app.models.device import Device
    from app.models.user import User


class RiskAssessment(Base, TimestampMixin):
    """Historical or current risk evaluation snapshot for a device or entire network."""

    __tablename__ = "risk_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )
    device_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 - 100.0
    exposure_subscore: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    vulnerability_subscore: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    anomaly_subscore: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    critical_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    open_risky_ports_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    score_breakdown: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    summary_notes: Mapped[str] = mapped_column(String(500), default="", nullable=False)

    # Relationships
    device: Mapped[Optional["Device"]] = relationship("Device", back_populates="risk_assessments")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="risk_assessments")

