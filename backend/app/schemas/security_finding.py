"""Security finding Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import FindingStatus, Severity


class SecurityFindingBase(BaseModel):
    """Base schema for a security risk finding."""

    title: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Short title of the finding",
    )

    category: str = Field(
        default="General Security",
        max_length=100,
        description="Finding category",
    )

    severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Finding severity level",
    )

    status: FindingStatus = Field(
        default=FindingStatus.OPEN,
        description="Current remediation status",
    )

    description: str = Field(
        ...,
        min_length=1,
        description="Detailed explanation of the risk",
    )

    remediation_steps: str = Field(
        default="",
        description="Prescriptive defensive mitigation instructions",
    )

    cve_id: str = Field(
        default="",
        max_length=50,
        description="Associated CVE identifier if applicable",
    )

    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evidence supporting the security finding",
    )


class SecurityFindingCreate(SecurityFindingBase):
    """Schema for creating a security finding."""

    device_id: uuid.UUID


class SecurityFindingUpdate(BaseModel):
    """Schema for updating a security finding."""

    title: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=255,
    )

    severity: Optional[Severity] = None

    status: Optional[FindingStatus] = None

    description: Optional[str] = None

    remediation_steps: Optional[str] = None

    cve_id: Optional[str] = Field(
        default=None,
        max_length=50,
    )

    evidence: Optional[Dict[str, Any]] = None


class SecurityFindingResponse(SecurityFindingBase):
    """Schema for returning security finding data."""

    id: uuid.UUID

    device_id: uuid.UUID

    created_at: datetime

    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )