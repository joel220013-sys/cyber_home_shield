"""Scan job Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.core.security import is_rfc1918_private_subnet, is_rfc1918_private_ip
from app.models.enums import ScanStatus, ScanType


class ScanJobBase(BaseModel):
    """Base schema for scan job execution."""

    target_subnet: str = Field(..., description="Target private CIDR subnet or single IP to defensively scan")
    scan_type: ScanType = Field(default=ScanType.DISCOVERY, description="Depth/type of authorized defensive scan")

    @field_validator("scan_type", mode="before")
    @classmethod
    def parse_scan_type(cls, v: Any) -> Any:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            if hasattr(ScanType, v_upper):
                return getattr(ScanType, v_upper)
        return v

    @field_validator("target_subnet")
    @classmethod
    def validate_target_scope(cls, v: str) -> str:
        clean = v.strip()
        if "/" in clean:
            if not is_rfc1918_private_subnet(clean):
                raise ValueError(
                    f"Subnet '{clean}' is not an authorized RFC 1918 private network range."
                )
        else:
            if not is_rfc1918_private_ip(clean):
                raise ValueError(
                    f"IP '{clean}' is not an authorized RFC 1918 private IPv4 address."
                )
        return clean


class ScanJobCreate(ScanJobBase):
    """Schema for requesting a new scan job."""
    pass


class ScanJobResponse(ScanJobBase):
    """Schema for returning scan job details."""

    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    status: ScanStatus
    devices_found: int = Field(default=0, ge=0)
    ports_scanned: int = Field(default=0, ge=0)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    summary_findings: Dict[str, Any] = Field(default_factory=dict)
    error_message: str = ""
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

