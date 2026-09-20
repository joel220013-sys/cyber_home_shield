"""Pydantic schemas for Honeypot & Deception Subsystem."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import Protocol, Severity


class HoneypotServiceStatus(BaseModel):
    """Status details for a single honeypot deception trap."""
    id: str = Field(..., description="Service identifier (e.g. iot_gateway, fake_ssh, camera_rtsp)")
    name: str = Field(..., description="Human readable service name")
    service_type: str = Field(..., description="Trap archetype (HTTP, SSH, CAMERA)")
    port: int = Field(..., description="Listening port number")
    running: bool = Field(..., description="Whether trap listener/simulator is active")
    description: str = Field(..., description="Decoy service description")
    interaction_count: int = Field(default=0, description="Total interactions captured by trap")


class HoneypotStatusResponse(BaseModel):
    """Aggregate status for the Honeypot deception subsystem."""
    enabled: bool = Field(..., description="Global honeypot feature flag status")
    running: bool = Field(..., description="Whether honeypot traps are currently active")
    bind_host: str = Field(..., description="Bound IP address for honeypot listeners")
    lan_ip: Optional[str] = Field(default="127.0.0.1", description="Resolved reachable LAN IPv4 address")
    decoy_profile: Optional[str] = Field(default="realistic_iot", description="Active deception banner profile")
    services: List[HoneypotServiceStatus] = Field(default_factory=list)
    total_events: int = Field(default=0, description="Total captured deception events")
    high_severity_events: int = Field(default=0, description="Count of HIGH and CRITICAL severity events")
    last_interaction: Optional[datetime] = Field(default=None, description="Timestamp of latest interaction")


class HoneypotEventBase(BaseModel):
    """Base schema for honeypot deception events."""
    honeypot_id: str = Field(..., description="Identifier of the targeted decoy trap")
    source_ip: str = Field(..., description="Source IPv4 address of probe")
    source_port: int = Field(default=0, description="Source port of incoming probe")
    destination_port: int = Field(..., description="Target decoy port")
    protocol: Protocol = Field(default=Protocol.TCP)
    interaction_type: str = Field(
        ...,
        description="Interaction classification (connection, http_request, login_attempt, admin_endpoint_access, camera_access, ssh_connection, repeated_connection, suspicious_request)",
    )
    endpoint: Optional[str] = Field(default="", description="Targeted URL endpoint (for HTTP/Camera traps)")
    user_agent: Optional[str] = Field(default="", description="Client User-Agent header (if applicable)")
    payload_sample: str = Field(default="", description="Sanitized payload excerpt (strictly devoid of passwords/secrets)")
    metadata_fields: Dict[str, Any] = Field(default_factory=dict, description="Safe structured interaction telemetry")
    severity: Severity = Field(default=Severity.LOW)


class HoneypotEventCreate(HoneypotEventBase):
    """Schema for recording a new honeypot event."""
    user_id: Optional[uuid.UUID] = None


class HoneypotEventResponse(HoneypotEventBase):
    """Schema for public honeypot event responses."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    event_timestamp: datetime
    created_at: datetime


class HoneypotStartRequest(BaseModel):
    """Payload to start honeypot traps."""
    bind_host: Optional[str] = Field(default=None, description="Custom bind host (must be 127.0.0.1 unless non-local explicitly allowed)")


class HoneypotStartResponse(BaseModel):
    """Response after starting honeypot traps."""
    status: str = "started"
    running: bool = True
    bind_host: str
    active_services: List[str]
    message: str


class HoneypotStopResponse(BaseModel):
    """Response after stopping honeypot traps."""
    status: str = "stopped"
    running: bool = False
    message: str


class HoneypotAnalysisResponse(BaseModel):
    """NVIDIA Nemotron AI explanation of honeypot deception event."""
    event_id: uuid.UUID
    summary: str
    pattern_detected: str
    severity: Severity
    defensive_implications: List[str]
    recommended_actions: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    model_used: str


class HoneypotSimulateRequest(BaseModel):
    """Safe testing payload to simulate a decoy probe."""
    trap_type: str = Field(
        default="iot_gateway",
        description="Trap to target (iot_gateway, fake_ssh, camera_rtsp)",
    )
    source_ip: Optional[str] = Field(default="192.168.1.199", description="Simulated probe source IP")
    interaction_type: Optional[str] = Field(default="login_attempt", description="Type of probe")
    endpoint: Optional[str] = Field(default="/login", description="Targeted endpoint")

