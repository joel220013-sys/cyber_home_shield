"""Security Finding ORM Model."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    Enum,
    ForeignKey,
    JSON,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from app.db.base import Base, TimestampMixin
from app.models.enums import FindingStatus, Severity


if TYPE_CHECKING:
    from app.models.device import Device


class SecurityFinding(Base, TimestampMixin):
    """
    Defensive security risk or vulnerability finding
    identified on a device.
    """

    __tablename__ = "security_findings"

    # ========================================================================
    # PRIMARY KEY
    # ========================================================================

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # ========================================================================
    # DEVICE RELATION
    # ========================================================================

    device_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "devices.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # ========================================================================
    # FINDING INFORMATION
    # ========================================================================

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(100),
        default="General Security",
        nullable=False,
    )

    # ========================================================================
    # SEVERITY
    # ========================================================================

    severity: Mapped[Severity] = mapped_column(
        Enum(
            Severity,
            name="severity_enum",
            native_enum=False,
        ),
        default=Severity.MEDIUM,
        nullable=False,
    )

    # ========================================================================
    # STATUS
    # ========================================================================

    status: Mapped[FindingStatus] = mapped_column(
        Enum(
            FindingStatus,
            name="finding_status_enum",
            native_enum=False,
        ),
        default=FindingStatus.OPEN,
        nullable=False,
    )

    # ========================================================================
    # DESCRIPTION
    # ========================================================================

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # ========================================================================
    # REMEDIATION
    # ========================================================================

    remediation_steps: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    # ========================================================================
    # CVE
    # ========================================================================

    cve_id: Mapped[str] = mapped_column(
        String(50),
        default="",
        nullable=False,
    )

    # ========================================================================
    # EVIDENCE
    # ========================================================================

    evidence: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    # ========================================================================
    # RELATIONSHIP
    # ========================================================================

    device: Mapped["Device"] = relationship(
        "Device",
        back_populates="findings",
    )