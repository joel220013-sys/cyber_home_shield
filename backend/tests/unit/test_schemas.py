"""Test Pydantic schemas validation and boundaries."""

import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from app.models.enums import DeviceType, FindingStatus, Protocol, ScanStatus, ScanType, Severity
from app.schemas.device import DeviceCreate, DeviceUpdate
from app.schemas.open_port import OpenPortBase, OpenPortCreate
from app.schemas.risk_assessment import RiskAssessmentBase
from app.schemas.scan_job import ScanJobCreate
from app.schemas.security_finding import SecurityFindingBase, SecurityFindingCreate
from app.schemas.user import UserLoginRequest, UserRegisterRequest, UserUpdateRequest


def test_device_create_valid():
    """Verify valid device creation schema."""
    dev = DeviceCreate(
        ip_address="192.168.1.100",
        mac_address="00:11:22:33:44:55",
        hostname="smart-tv.home",
        vendor="Samsung Electronics",
        device_type=DeviceType.SMART_TV,
        risk_score=25.5,
    )
    assert dev.ip_address == "192.168.1.100"
    assert dev.risk_score == 25.5
    assert dev.device_type == DeviceType.SMART_TV


def test_device_create_invalid_public_ip():
    """Verify device schema rejects public WAN IPs."""
    with pytest.raises(ValidationError) as exc:
        DeviceCreate(
            ip_address="8.8.8.8",
            mac_address="AA:BB:CC:DD:EE:FF",
        )
    assert "RFC 1918" in str(exc.value)


def test_risk_score_bounds():
    """Verify risk scores must strictly remain within 0.0 to 100.0."""
    # Valid bounds
    r_zero = RiskAssessmentBase(overall_score=0.0)
    assert r_zero.overall_score == 0.0

    r_hundred = RiskAssessmentBase(overall_score=100.0)
    assert r_hundred.overall_score == 100.0

    # Negative score rejection
    with pytest.raises(ValidationError):
        RiskAssessmentBase(overall_score=-5.0)

    # Over 100 rejection
    with pytest.raises(ValidationError):
        RiskAssessmentBase(overall_score=105.0)


def test_open_port_range_validation():
    """Verify port numbers are bounded to 1-65535."""
    port = OpenPortBase(port_number=443, service_name="https", protocol=Protocol.TCP)
    assert port.port_number == 443

    # Invalid port 0
    with pytest.raises(ValidationError):
        OpenPortBase(port_number=0)

    # Invalid port > 65535
    with pytest.raises(ValidationError):
        OpenPortBase(port_number=70000)


def test_scan_job_scope_validation():
    """Verify scan job schema validates defensive RFC1918 scope."""
    scan = ScanJobCreate(
        target_subnet="192.168.1.0/24",
        scan_type=ScanType.STANDARD_AUDIT,
    )
    assert scan.target_subnet == "192.168.1.0/24"

    # Reject WAN subnet
    with pytest.raises(ValidationError):
        ScanJobCreate(target_subnet="1.2.3.0/24")


def test_security_finding_schema():
    """Verify security finding creation and validation."""
    finding = SecurityFindingCreate(
        device_id=uuid.uuid4(),
        title="Unencrypted Telnet Port Open",
        category="Insecure Protocol",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        description="Port 23 is open allowing plaintext communication.",
        remediation_steps="Disable Telnet and use SSH (port 22) instead.",
    )
    assert finding.severity == Severity.HIGH
    assert finding.status == FindingStatus.OPEN


def test_user_register_schema_validation():
    """Verify user registration schema enforces email, password length, and RFC 1918 scope."""
    valid = UserRegisterRequest(
        email="admin@shield.local",
        password="LongEnoughPassword123!",
        full_name="Admin User",
        authorized_network_scope="192.168.1.0/24",
    )
    assert valid.email == "admin@shield.local"
    assert valid.authorized_network_scope == "192.168.1.0/24"

    # Invalid scope (public IP)
    with pytest.raises(ValidationError):
        UserRegisterRequest(
            email="admin@shield.local",
            password="LongEnoughPassword123!",
            authorized_network_scope="8.8.8.0/24",
        )

    # Short password
    with pytest.raises(ValidationError):
        UserRegisterRequest(
            email="admin@shield.local",
            password="short",
        )


def test_user_login_schema():
    """Verify user login schema."""
    login = UserLoginRequest(email="user@shield.local", password="Password123!")
    assert login.email == "user@shield.local"
    assert login.password == "Password123!"

