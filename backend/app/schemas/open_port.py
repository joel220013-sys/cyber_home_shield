"""Open port Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import Protocol


class OpenPortBase(BaseModel):
    """Base schema for an open port entry."""

    port_number: int = Field(..., ge=1, le=65535, description="Port number (1-65535)")
    protocol: Protocol = Field(default=Protocol.TCP, description="Transport protocol")
    service_name: str = Field(default="unknown", max_length=100, description="Identified service name")
    banner: str = Field(default="", description="Service banner or response header")
    is_risky: bool = Field(default=False, description="Flag indicating if the open port carries security risk")
    risk_reason: str = Field(default="", max_length=255, description="Reason for risk designation")


class OpenPortCreate(OpenPortBase):
    """Schema for recording a newly discovered port."""

    device_id: uuid.UUID


class OpenPortResponse(OpenPortBase):
    """Schema for returning open port information."""

    id: uuid.UUID
    device_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

