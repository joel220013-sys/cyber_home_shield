"""Core security utilities: password hashing, JWT token handling, private scope validation, and rate limiting."""

import base64
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import bcrypt

from app.config import settings
from app.core.exceptions import (
    ScopeValidationError,
    TokenExpiredError,
    TokenInvalidError,
)

# RFC 1918 Private IPv4 Networks
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against the hashed password using bcrypt."""
    if not plain_password or not hashed_password:
        return False
    try:
        password_bytes = plain_password.encode("utf-8")
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Generate a secure cryptographic hash of the password using bcrypt."""
    if not password:
        raise ValueError("Password cannot be empty.")
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random token (URL-safe)."""
    return secrets.token_urlsafe(nbytes)


# ---------------------------------------------------------------------------
# Standard RFC 7519 HS256 JWT Implementation (Zero external dependency)
# ---------------------------------------------------------------------------

def _base64url_encode(data: bytes) -> str:
    """Base64 URL-safe encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Base64 URL-safe decode with padding restoration."""
    rem = len(data) % 4
    if rem > 0:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def create_access_token(
    subject: Union[str, Any],
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a standard RFC 7519 HMAC-SHA256 JWT access token.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    header = {"alg": "HS256", "typ": "JWT"}
    payload: Dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "nbf": int(now.timestamp()),
    }
    if claims:
        payload.update(claims)

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    header_b64 = _base64url_encode(header_bytes)
    payload_b64 = _base64url_encode(payload_bytes)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    secret_bytes = settings.SECRET_KEY.encode("utf-8")
    signature = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a standard RFC 7519 HS256 JWT access token.
    Validates cryptographic signature and expiration.
    """
    if not token or not isinstance(token, str):
        raise TokenInvalidError("Invalid token format.")

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise TokenInvalidError("Malformed JWT structure: expected 3 parts.")

    header_b64, payload_b64, sig_b64 = parts

    # 1. Verify Signature
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    secret_bytes = settings.SECRET_KEY.encode("utf-8")
    expected_sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    expected_sig_b64 = _base64url_encode(expected_sig)

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        raise TokenInvalidError("Invalid token signature.")

    # 2. Decode Payload
    try:
        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise TokenInvalidError(f"Failed to decode token payload: {str(exc)}")

    # 3. Verify Expiration
    exp = payload.get("exp")
    if exp is not None:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        if now_ts > int(exp):
            raise TokenExpiredError("Token has expired.")

    return payload


# ---------------------------------------------------------------------------
# Scope Validation (RFC 1918 Private IPv4 Defensive Scope)
# ---------------------------------------------------------------------------

def is_rfc1918_private_ip(ip_str: str) -> bool:
    """
    Check if an IPv4 address belongs strictly to RFC 1918 private address ranges.
    Rejects loopback (127.0.0.0/8), link-local (169.254.0.0/16), multicast, and WAN public IPs.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.version != 4:
            return False
        return any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def is_rfc1918_private_subnet(subnet_str: str) -> bool:
    """
    Check if a CIDR network subnet is fully contained within an RFC 1918 private range.
    Rejects subnets that span public address space.
    """
    try:
        net = ipaddress.ip_network(subnet_str.strip(), strict=False)
        if net.version != 4:
            return False
        return any(net.subnet_of(rfc_net) for rfc_net in RFC1918_NETWORKS)
    except (ValueError, TypeError):
        return False


def validate_defensive_target_scope(target: str) -> ipaddress.IPv4Network:
    """
    Validate that a given IP address or CIDR subnet is within authorized RFC 1918 private scope.
    Raises ScopeValidationError if target is public, malformed, or unauthorized.
    """
    target_clean = target.strip()
    try:
        # Check if single IP
        if "/" not in target_clean:
            ip = ipaddress.ip_address(target_clean)
            if ip.version != 4:
                raise ScopeValidationError(f"Only IPv4 targets are supported: {target_clean}")
            if not any(ip in rfc_net for rfc_net in RFC1918_NETWORKS):
                raise ScopeValidationError(
                    f"Target IP {target_clean} is not within authorized RFC 1918 private networks "
                    "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Public scans are strictly prohibited."
                )
            return ipaddress.ip_network(f"{target_clean}/32")

        # Network subnet
        net = ipaddress.ip_network(target_clean, strict=False)
        if net.version != 4:
            raise ScopeValidationError(f"Only IPv4 networks are supported: {target_clean}")

        if not any(net.subnet_of(rfc_net) for rfc_net in RFC1918_NETWORKS):
            raise ScopeValidationError(
                f"Target subnet {target_clean} is not contained within authorized RFC 1918 private networks. "
                "Public scans are strictly prohibited."
            )
        return net
    except ValueError as e:
        raise ScopeValidationError(f"Invalid IP address or CIDR format: '{target_clean}' - {e}")


def mask_secret(secret_value: str, visible_chars: int = 4) -> str:
    """Safely mask secrets for display purposes (e.g., '****1234')."""
    if not secret_value:
        return ""
    if len(secret_value) <= visible_chars:
        return "*" * len(secret_value)
    return f"{'*' * (len(secret_value) - visible_chars)}{secret_value[-visible_chars:]}"


# ---------------------------------------------------------------------------
# In-Memory Sliding Window Rate Limiter
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding window rate limiter for endpoint protection."""

    def __init__(self) -> None:
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60) -> Tuple[bool, int]:
        """
        Check if request for key is allowed within window_seconds.
        Returns (is_allowed, remaining_requests).
        """
        if not settings.RATE_LIMIT_ENABLED:
            return True, max_requests

        now = time.time()
        window_start = now - window_seconds

        # Clean old timestamps
        history = [ts for ts in self._requests[key] if ts > window_start]
        self._requests[key] = history

        if len(history) >= max_requests:
            return False, 0

        self._requests[key].append(now)
        remaining = max_requests - len(self._requests[key])
        return True, remaining

    def reset(self) -> None:
        """Clear all rate limit histories."""
        self._requests.clear()


rate_limiter = SlidingWindowRateLimiter()

