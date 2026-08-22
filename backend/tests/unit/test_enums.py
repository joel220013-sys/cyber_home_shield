"""Test domain enum representations and consistency."""

from app.models.enums import (
    DeviceType,
    FindingStatus,
    Protocol,
    ScanStatus,
    ScanType,
    Severity,
)


def test_device_type_enum():
    """Verify DeviceType members and string representations."""
    expected = {
        "ROUTER", "IOT", "WORKSTATION", "MOBILE", "SMART_TV",
        "STORAGE", "GAMING_CONSOLE", "PRINTER", "UNKNOWN"
    }
    actual = {item.value for item in DeviceType}
    assert actual == expected
    assert str(DeviceType.ROUTER) == "ROUTER"


def test_scan_enums():
    """Verify ScanStatus and ScanType members."""
    status_values = {s.value for s in ScanStatus}
    assert {"PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"}.issubset(status_values)

    type_values = {t.value for t in ScanType}
    assert {"DISCOVERY", "STANDARD_AUDIT", "DEEP_PROFILE"}.issubset(type_values)


def test_severity_levels():
    """Verify standard CVSS-aligned severity hierarchy values."""
    assert Severity.CRITICAL.value == "CRITICAL"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.LOW.value == "LOW"
    assert Severity.INFO.value == "INFO"


def test_protocol_enum():
    """Verify network protocols."""
    assert Protocol.TCP.value == "TCP"
    assert Protocol.UDP.value == "UDP"
    assert Protocol.ICMP.value == "ICMP"

