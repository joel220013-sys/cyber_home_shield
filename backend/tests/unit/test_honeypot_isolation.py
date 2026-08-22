"""Unit tests for Honeypot Isolation, Payload Sanitization, and Deterministic Classification."""

import pytest
from app.core.exceptions import ScopeValidationError
from app.models.enums import Severity
from app.services.honeypot.isolation import (
    classify_interaction,
    sanitize_honeypot_payload,
    sanitize_metadata,
    validate_honeypot_bind_host,
)


def test_validate_honeypot_bind_host_loopback():
    """Verify loopback addresses are accepted by default."""
    assert validate_honeypot_bind_host("127.0.0.1") == "127.0.0.1"
    assert validate_honeypot_bind_host("localhost") == "localhost"
    assert validate_honeypot_bind_host("::1") == "::1"


def test_validate_honeypot_bind_host_unspecified_rejected():
    """Verify 0.0.0.0 is rejected when allow_non_local is False."""
    with pytest.raises(ScopeValidationError) as exc:
        validate_honeypot_bind_host("0.0.0.0", allow_non_local=False)
    assert "prohibited by default" in str(exc.value)

    # Allowed when explicitly authorized
    assert validate_honeypot_bind_host("0.0.0.0", allow_non_local=True) == "0.0.0.0"


def test_validate_honeypot_bind_host_wan_prohibited():
    """Verify public WAN addresses are strictly rejected under all circumstances."""
    with pytest.raises(ScopeValidationError) as exc:
        validate_honeypot_bind_host("8.8.8.8", allow_non_local=True)
    assert "strictly prohibited" in str(exc.value)


def test_sanitize_honeypot_payload_redacts_credentials():
    """Verify passwords, authorization tokens, and secrets are redacted from payloads."""
    raw_payload = "username=admin&password=SuperSecretPassword123!&token=xyz987"
    sanitized = sanitize_honeypot_payload(raw_payload)

    assert "SuperSecretPassword123!" not in sanitized
    assert "[REDACTED]" in sanitized
    assert "username=admin" in sanitized


def test_sanitize_honeypot_payload_redacts_auth_headers():
    """Verify Authorization Bearer headers are redacted."""
    raw_headers = "GET /admin HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.test\r\nCookie: session_id=secret123"
    sanitized = sanitize_honeypot_payload(raw_headers)

    assert "eyJhbGciOiJIUzI1NiJ9" not in sanitized
    assert "secret123" not in sanitized
    assert "[REDACTED]" in sanitized


def test_sanitize_metadata_recursive():
    """Verify nested dictionary metadata is scrubbed of sensitive keys."""
    meta = {
        "client_ip": "192.168.1.50",
        "auth_attempt": {
            "user": "root",
            "password": "Password99!",
            "api_key": "sk-1234567890",
        },
        "tags": ["honeypot", "login_probe"],
    }
    cleaned = sanitize_metadata(meta)

    assert cleaned["client_ip"] == "192.168.1.50"
    assert cleaned["auth_attempt"]["password"] == "[REDACTED]"
    assert cleaned["auth_attempt"]["api_key"] == "[REDACTED]"
    assert cleaned["auth_attempt"]["user"] == "root"


def test_classify_interaction_types():
    """Verify deterministic interaction type and severity classification."""
    # Standard inspection
    itype, sev = classify_interaction("GET", "/", "", "TCP", "HTTP")
    assert itype == "http_request"
    assert sev == Severity.INFO

    # Login attempt
    itype, sev = classify_interaction("POST", "/login", "user=admin", "TCP", "HTTP")
    assert itype == "login_attempt"
    assert sev == Severity.MEDIUM

    # Admin portal probing
    itype, sev = classify_interaction("GET", "/admin/config", "", "TCP", "HTTP")
    assert itype == "admin_endpoint_access"
    assert sev == Severity.MEDIUM

    itype, sev = classify_interaction("POST", "/admin/settings", "action=save", "TCP", "HTTP")
    assert itype == "admin_endpoint_access"
    assert sev == Severity.HIGH

    # Traversal injection attempt
    itype, sev = classify_interaction("GET", "/../../etc/passwd", "", "TCP", "HTTP")
    assert itype == "suspicious_request"
    assert sev == Severity.HIGH

    # SSH probe
    itype, sev = classify_interaction("CONNECT", "ssh", "SSH-2.0-libssh", "SSH", "SSH")
    assert itype == "ssh_connection"
    assert sev in (Severity.LOW, Severity.INFO)

    # Camera probe
    itype, sev = classify_interaction("GET", "/snapshot", "", "TCP", "CAMERA")
    assert itype == "camera_access"
    assert sev == Severity.LOW

