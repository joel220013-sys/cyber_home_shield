"""Device Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.core.security import is_rfc1918_private_ip
from app.models.enums import DeviceType
from app.schemas.open_port import OpenPortResponse
from app.schemas.security_finding import SecurityFindingResponse


class DeviceBase(BaseModel):
    """Base device fields."""

    ip_address: str = Field(..., description="IPv4 address within authorized RFC 1918 private space")
    mac_address: str = Field(default="", max_length=17, description="Device MAC address (AA:BB:CC:DD:EE:FF)")
    hostname: str = Field(default="", max_length=255, description="Resolved network hostname")
    custom_name: str = Field(default="", max_length=255, description="User-assigned friendly name")
    vendor: str = Field(default="Unknown Vendor", max_length=255, description="Hardware manufacturer")
    vendor_source: str = Field(default="", max_length=100)
    device_role: str = Field(default="", max_length=100)
    identity_confidence: str = Field(default="LOW", max_length=20)
    identity_evidence: Dict[str, Any] = Field(default_factory=dict)
    device_type: DeviceType = Field(default=DeviceType.UNKNOWN, description="Classified device archetype")
    is_trusted: bool = Field(default=False, description="Whether device is verified by user")
    is_online: bool = Field(default=True, description="Current online reachability status")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Calculated security risk score (0-100)")

    @field_validator("ip_address")
    @classmethod
    def validate_private_ip(cls, v: str) -> str:
        clean_ip = v.strip()
        if not is_rfc1918_private_ip(clean_ip):
            raise ValueError(
                f"IP address '{clean_ip}' must be an authorized RFC 1918 private IPv4 address "
                "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
            )
        return clean_ip


class DeviceCreate(DeviceBase):
    """Schema for enrolling or registering a discovered device."""
    pass


class DeviceUpdate(BaseModel):
    """Schema for updating an existing device profile."""

    custom_name: Optional[str] = Field(default=None, max_length=255)
    device_type: Optional[DeviceType] = None
    is_trusted: Optional[bool] = None
    is_online: Optional[bool] = None
    vendor: Optional[str] = Field(default=None, max_length=255)
    hostname: Optional[str] = Field(default=None, max_length=255)


class DeviceResponse(DeviceBase):
    """Schema for returning device summary data."""

    id: uuid.UUID
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    ports: List[OpenPortResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class DeviceDetailResponse(DeviceResponse):
    """Extended device details with ports and security findings."""

    findings: List[SecurityFindingResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)

