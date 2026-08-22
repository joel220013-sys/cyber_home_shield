"""Test security utilities, password hashing, JWT operations, rate limiting, and RFC1918 scope validation."""

import time
from datetime import timedelta
import pytest
from app.core.exceptions import (
    ScopeValidationError,
    TokenExpiredError,
    TokenInvalidError,
)
from app.core.security import (
    SlidingWindowRateLimiter,
    create_access_token,
    decode_access_token,
    generate_secure_token,
    get_password_hash,
    is_rfc1918_private_ip,
    is_rfc1918_private_subnet,
    mask_secret,
    validate_defensive_target_scope,
    verify_password,
)


def test_password_hashing_and_verification():
    """Verify password hashing creates verifiable bcrypt hashes."""
    raw_password = "DefensiveSecurityPass#2026"
    hashed = get_password_hash(raw_password)

    assert hashed != raw_password
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_token_flow_success():
    """Verify creating and successfully decoding JWT tokens with claims."""
    subject = "12345678-1234-5678-1234-567812345678"
    claims = {"email": "admin@shield.local", "is_superuser": True}
    token = create_access_token(subject=subject, claims=claims, expires_delta=timedelta(minutes=15))

    assert isinstance(token, str)
    assert len(token.split(".")) == 3

    decoded = decode_access_token(token)
    assert decoded["sub"] == subject
    assert decoded["email"] == "admin@shield.local"
    assert decoded["is_superuser"] is True
    assert "exp" in decoded


def test_jwt_token_expired():
    """Verify decoding expired JWT token raises TokenExpiredError."""
    token = create_access_token(
        subject="test_user",
        expires_delta=timedelta(seconds=-10),  # expired 10s ago
    )
    with pytest.raises(TokenExpiredError):
        decode_access_token(token)


def test_jwt_token_tampered():
    """Verify tampered JWT token signature raises TokenInvalidError."""
    token = create_access_token(subject="original_user")
    parts = token.split(".")
    # Alter payload part
    tampered = f"{parts[0]}.eyJzdWIiOiAiaGFja2VyIn0.{parts[2]}"
    with pytest.raises(TokenInvalidError):
        decode_access_token(tampered)


def test_rate_limiter_sliding_window():
    """Verify SlidingWindowRateLimiter enforces request thresholds."""
    limiter = SlidingWindowRateLimiter()
    key = "client_192.168.1.100"

    # First 3 requests succeed
    allowed1, rem1 = limiter.is_allowed(key, max_requests=3, window_seconds=2)
    allowed2, rem2 = limiter.is_allowed(key, max_requests=3, window_seconds=2)
    allowed3, rem3 = limiter.is_allowed(key, max_requests=3, window_seconds=2)
    assert allowed1 is True and rem1 == 2
    assert allowed2 is True and rem2 == 1
    assert allowed3 is True and rem3 == 0

    # 4th request exceeds rate limit
    allowed4, rem4 = limiter.is_allowed(key, max_requests=3, window_seconds=2)
    assert allowed4 is False
    assert rem4 == 0


def test_rfc1918_private_ip_acceptance():
    """Verify standard RFC1918 private IPv4 addresses are accepted."""
    valid_private_ips = [
        "10.0.0.1",
        "10.254.100.5",
        "172.16.0.1",
        "172.24.10.15",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.0.254",
        "192.168.100.50",
    ]
    for ip in valid_private_ips:
        assert is_rfc1918_private_ip(ip) is True, f"Failed for {ip}"


def test_public_and_non_defensive_ip_rejection():
    """Verify public WAN and unauthorized IP addresses are strictly rejected."""
    invalid_ips = [
        "8.8.8.8",          # Google Public DNS
        "1.1.1.1",          # Cloudflare DNS
        "142.250.190.46",   # Google Web
        "169.254.1.1",      # Link-local APIPA
        "127.0.0.1",        # Loopback
        "224.0.0.1",        # Multicast
        "255.255.255.255",  # Broadcast
        "invalid-ip-string",
    ]
    for ip in invalid_ips:
        assert is_rfc1918_private_ip(ip) is False, f"Should reject {ip}"


def test_rfc1918_subnet_validation():
    """Verify private network subnets are accepted and public/mixed subnets rejected."""
    assert is_rfc1918_private_subnet("192.168.1.0/24") is True
    assert is_rfc1918_private_subnet("10.0.0.0/16") is True
    assert is_rfc1918_private_subnet("172.16.0.0/20") is True

    # Rejection of public or invalid CIDRs
    assert is_rfc1918_private_subnet("8.8.8.0/24") is False
    assert is_rfc1918_private_subnet("0.0.0.0/0") is False
    assert is_rfc1918_private_subnet("127.0.0.0/8") is False


def test_validate_defensive_target_scope_success():
    """Verify validate_defensive_target_scope returns valid IPv4Network object."""
    scope = validate_defensive_target_scope("192.168.1.0/24")
    assert str(scope) == "192.168.1.0/24"

    single_ip_scope = validate_defensive_target_scope("10.0.5.12")
    assert str(single_ip_scope) == "10.0.5.12/32"


def test_validate_defensive_target_scope_rejections():
    """Verify validate_defensive_target_scope raises ScopeValidationError for WAN targets."""
    with pytest.raises(ScopeValidationError):
        validate_defensive_target_scope("8.8.8.8")

    with pytest.raises(ScopeValidationError):
        validate_defensive_target_scope("203.0.113.0/24")

    with pytest.raises(ScopeValidationError):
        validate_defensive_target_scope("not-a-valid-ip")


def test_mask_secret():
    """Verify secret masking leaves only trailing characters visible."""
    masked = mask_secret("nvapi-1234567890abcdef", visible_chars=4)
    assert masked.endswith("cdef")
    assert "1234567890" not in masked


def test_generate_secure_token():
    """Verify token generation length and randomness."""
    t1 = generate_secure_token()
    t2 = generate_secure_token()
    assert len(t1) >= 32
    assert t1 != t2

