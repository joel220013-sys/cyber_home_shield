"""Network telemetry event schemas."""

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import Protocol, Severity


class NetworkEventBase(BaseModel):
    """Base schema for a network telemetry event."""

    event_timestamp: datetime
    source_ip: str = Field(..., max_length=45)
    destination_ip: str = Field(..., max_length=45)
    source_port: int = Field(default=0, ge=0, le=65535)
    destination_port: int = Field(..., ge=1, le=65535)
    protocol: Protocol = Field(default=Protocol.TCP)
    bytes_transferred: int = Field(default=0, ge=0)
    is_anomaly: bool = Field(default=False)
    anomaly_reason: str = Field(default="", max_length=255)
    severity: Severity = Field(default=Severity.INFO)


class NetworkEventCreate(NetworkEventBase):
    """Schema for registering a network event."""

    device_id: Optional[uuid.UUID] = None


class NetworkEventResponse(NetworkEventBase):
    """Schema for returning network event telemetry."""

    id: uuid.UUID
    device_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

