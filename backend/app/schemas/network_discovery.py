"""Schemas for authenticated local network discovery."""

from typing import List, Optional, Literal

from pydantic import BaseModel, ConfigDict, Field


class NetworkDiscoveryRequest(BaseModel):
    """Empty request contract; the backend detector supplies the target."""

    model_config = ConfigDict(extra="forbid")


class PostureEvidence(BaseModel):
    """A real observation used for an identity or posture decision."""

    category: Literal["hostname", "vendor", "role", "reachability", "security", "identity"]
    source: str
    detail: str


class DiscoveredNetworkDevice(BaseModel):
    """Observed device metadata; unknown values remain null."""

    model_config = ConfigDict(extra="forbid")

    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    status: str
    mac_type: str = "unknown"
    classification: str = "UNIDENTIFIED"
    evidence_state: str = "Hostname unavailable - behavioral fingerprinting active"
    risk_level: str = "LOW"
    risk_score: float = 0.0
    confidence: str = "MEDIUM"
    evidence: List[str] = Field(default_factory=list)
    reason: str = "No suspicious security evidence observed"
    identity_classification: str = "UNIDENTIFIED"
    device_role: str = "Unknown"
    posture_evidence: List[PostureEvidence] = Field(default_factory=list)

    # Nmap enrichment fields
    hop_count: Optional[int] = None
    """Estimated number of network hops to this device (derived from TTL)."""
    ttl: Optional[int] = None
    """Raw observed TTL value from the ICMP reply."""
    os_guess: Optional[str] = None
    """Best-effort OS fingerprint from nmap (empty when unavailable)."""


class NetworkDiscoveryResponse(BaseModel):
    """Bounded discovery result for the detector-provided network."""

    model_config = ConfigDict(extra="forbid")

    status: str
    network: Optional[str] = None
    devices: List[DiscoveredNetworkDevice]
    total_devices: int = 0
    """Total number of devices discovered (convenience field = len(devices))."""
    scan_method: str = "arp_icmp"
    """Scan method used: 'arp_icmp', 'nmap', or 'arp_icmp+nmap'."""
