"""Discovery domain models and data transfer schemas."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.security import (
    is_rfc1918_private_ip,
    is_rfc1918_private_subnet,
)
from app.models.enums import Protocol


# ============================================================================
# SERVICE STATE
# ============================================================================


class ServiceState(str, Enum):
    """Observed state of a probed network service."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


# ============================================================================
# DISCOVERY EVIDENCE
# ============================================================================


class DiscoveryEvidence(BaseModel):
    """Observed diagnostic proof for host or service reachability."""

    method: str = Field(
        ...,
        description=(
            "Method used, for example "
            "'tcp_connect' or 'arp_table'."
        ),
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    raw_response: str = Field(
        default="",
        description="Non-sensitive diagnostic response or banner.",
    )

    response_time_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Latency in milliseconds.",
    )

    model_config = ConfigDict(frozen=True)


# ============================================================================
# DISCOVERED SERVICE
# ============================================================================


class DiscoveredService(BaseModel):
    """Network service observed during conservative audit."""

    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Port number (1-65535).",
    )

    protocol: Protocol = Field(
        default=Protocol.TCP
    )

    state: ServiceState = Field(
        default=ServiceState.UNKNOWN
    )

    service_name: str = Field(
        default="unknown",
        description="Identified service name.",
    )

    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    evidence: Optional[DiscoveryEvidence] = None

    model_config = ConfigDict(
        from_attributes=True
    )


# ============================================================================
# DISCOVERED HOST
# ============================================================================


class DiscoveredHost(BaseModel):
    """Discovered network endpoint profile."""

    ip_address: str = Field(
        ...,
        description="IPv4 address within authorized RFC 1918 scope.",
    )

    mac_address: str = Field(
        default="",
        description="MAC address if observed, otherwise empty.",
    )

    hostname: str = Field(
        default="",
        description="Resolved hostname if available.",
    )

    is_online: bool = Field(
        default=True
    )

    services: List[DiscoveredService] = Field(
        default_factory=list
    )

    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    discovery_method: str = Field(
        default="defensive_probe"
    )

    @field_validator("ip_address")
    @classmethod
    def validate_private_ip(cls, value: str) -> str:
        """Allow only RFC 1918 private IPv4 addresses."""

        clean = value.strip()

        if not is_rfc1918_private_ip(clean):
            raise ValueError(
                f"Host IP '{clean}' is outside "
                "authorized RFC 1918 private space."
            )

        return clean


# ============================================================================
# DISCOVERY TARGET
# ============================================================================


class DiscoveryTarget(BaseModel):
    """Validated target specification for defensive discovery."""

    target_subnet: str = Field(
        ...,
        description=(
            "CIDR subnet or single IPv4 address "
            "in RFC 1918 private space."
        ),
    )

    ports: List[int] = Field(
        default_factory=lambda: [
            22,
            53,
            80,
            443,
            445,
            554,
            631,
            8080,
            8443,
        ],
        description="Ports to conservatively audit.",
    )

    dry_run: bool = Field(
        default=False,
        description="Simulate without network transmission.",
    )

    max_hosts: int = Field(
        default=254,
        ge=1,
        le=1024,
        description="Maximum host inspection budget.",
    )

    timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Discovery timeout in seconds.",
    )

    @field_validator("target_subnet")
    @classmethod
    def validate_target(cls, value: str) -> str:
        """Validate the discovery target is private RFC 1918 space."""

        clean = value.strip()

        if "/" in clean:
            if not is_rfc1918_private_subnet(clean):
                raise ValueError(
                    f"Subnet '{clean}' is not an authorized "
                    "RFC 1918 private network."
                )
        else:
            if not is_rfc1918_private_ip(clean):
                raise ValueError(
                    f"IP '{clean}' is not an authorized "
                    "RFC 1918 private IPv4 address."
                )

        return clean

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: List[int]) -> List[int]:
        """Validate and normalize the configured port list."""

        if not ports:
            raise ValueError(
                "Port list cannot be empty."
            )

        for port in ports:
            if not isinstance(port, int):
                raise ValueError(
                    f"Invalid port value: {port!r}."
                )

            if not 1 <= port <= 65535:
                raise ValueError(
                    f"Invalid port number: {port}. "
                    "Must be between 1 and 65535."
                )

        # Remove duplicates and keep deterministic ordering.
        return sorted(set(ports))


# ============================================================================
# DISCOVERY STATISTICS
# ============================================================================


class DiscoveryStatistics(BaseModel):
    """Aggregate metrics recorded during a discovery run."""

    hosts_checked: int = Field(
        default=0,
        ge=0,
    )

    hosts_found: int = Field(
        default=0,
        ge=0,
    )

    services_checked: int = Field(
        default=0,
        ge=0,
    )

    services_found: int = Field(
        default=0,
        ge=0,
    )

    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
    )


# ============================================================================
# DISCOVERY RESULT
# ============================================================================


class DiscoveryResult(BaseModel):
    """Full outcome of a defensive discovery execution."""

    target: str

    started_at: datetime

    completed_at: datetime

    hosts: List[DiscoveredHost] = Field(
        default_factory=list
    )

    services: List[DiscoveredService] = Field(
        default_factory=list
    )

    evidence: List[DiscoveryEvidence] = Field(
        default_factory=list
    )

    errors: List[str] = Field(
        default_factory=list
    )

    statistics: DiscoveryStatistics = Field(
        default_factory=DiscoveryStatistics
    )


# ============================================================================
# DRY-RUN RESULT
# ============================================================================


class DryRunResult(BaseModel):
    """
    Detailed plan produced during dry-run mode.

    Dry-run mode performs zero network socket transmission.
    """

    target_subnet: str

    total_hosts_in_scope: int

    candidate_hosts: List[str]

    ports_to_check: List[int]

    network_operations_performed: Literal[0] = Field(
        default=0
    )

    execution_plan: str