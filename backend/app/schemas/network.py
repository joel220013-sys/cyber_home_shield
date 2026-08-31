"""Schemas for read-only local network detection."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class RouterDetectionResponse(BaseModel):
    """Network information detected on the machine running the backend."""

    model_config = ConfigDict(extra="forbid")

    status: str
    gateway_ip: Optional[str] = None
    local_ip: Optional[str] = None
    network_cidr: Optional[str] = None
    interface: Optional[str] = None
    connection_type: Optional[str] = None
    dhcp_server_ip: Optional[str] = None
    dns_server_ips: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
