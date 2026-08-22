"""Shared deterministic security rules for the risk engine."""

from typing import Dict


# ============================================================================
# DETERMINISTIC RISKY PORTS
# ============================================================================

DETERMINISTIC_RISKY_PORTS = {
    22,      # SSH
    80,      # HTTP
    445,     # SMB
    554,     # RTSP
    8080,    # HTTP alternate
}


# ============================================================================
# PORT EXPOSURE WEIGHTS
# ============================================================================

PORT_EXPOSURE_WEIGHTS: Dict[int, float] = {
    445: 35.0,   # SMB
    22: 20.0,    # SSH
    554: 20.0,   # RTSP
    80: 15.0,    # HTTP
    8080: 15.0,  # HTTP-alt
    631: 10.0,   # IPP
    53: 5.0,     # DNS
    443: 5.0,    # HTTPS
    8443: 5.0,   # HTTPS-alt
}


# ============================================================================
# DEFAULTS
# ============================================================================

DEFAULT_UNKNOWN_PORT_WEIGHT = 10.0

RISKY_WEIGHT_THRESHOLD = 15.0


# ============================================================================
# PORT DESCRIPTIONS
# ============================================================================

PORT_DESCRIPTIONS: Dict[int, str] = {
    445: (
        "SMB file-sharing protocol active "
        "(high administrative exposure)"
    ),
    22: (
        "SSH remote shell administrative "
        "service active"
    ),
    554: (
        "RTSP media streaming service active"
    ),
    80: (
        "HTTP plaintext unencrypted web "
        "interface exposed"
    ),
    8080: (
        "HTTP-alt unencrypted secondary "
        "web interface exposed"
    ),
    631: (
        "IPP network printing service exposed"
    ),
    53: (
        "DNS domain name resolution "
        "service active"
    ),
    443: (
        "HTTPS encrypted web management "
        "service active"
    ),
    8443: (
        "HTTPS-alt encrypted secondary "
        "web management interface active"
    ),
}


def get_port_exposure_weight(port: int) -> float:
    """Return deterministic exposure weight for a port."""
    return PORT_EXPOSURE_WEIGHTS.get(
        port,
        DEFAULT_UNKNOWN_PORT_WEIGHT,
    )


def is_deterministically_risky(port: int) -> bool:
    """Return whether a port is always considered security-relevant."""
    return port in DETERMINISTIC_RISKY_PORTS


def get_port_description(port: int) -> str:
    """Return a human-readable description for a port."""
    return PORT_DESCRIPTIONS.get(
        port,
        f"General TCP service on port {port}",
    )