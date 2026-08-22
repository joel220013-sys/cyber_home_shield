"""Honeypot Isolation & Sanitization Subsystem.

Enforces strict isolation policies:
- Localhost container-only binding validation
- Prevention of command/shell execution, proxying, SSRF, or packet forwarding
- Zero credential/password/secret persistence
- Deterministic event classification & severity scoring
"""

import ipaddress
import re
from typing import Any, Dict, List, Tuple
from app.core.exceptions import ScopeValidationError
from app.models.enums import Severity

# Redaction patterns for secrets, credentials, tokens
SENSITIVE_PATTERNS = [
    (re.compile(r"(password|passwd|pwd|pass|secret|token|api[_-]?key|bearer)[\s=:\"']+[^\s&,\"'>]+", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"(authorization:\s*bearer\s+)[^\s\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
]

SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/|win\.ini|cmd\.exe|/bin/sh|/bin/bash)", re.IGNORECASE),
    re.compile(r"(union\s+select|sleep\(|benchmark\(|'\s*or\s*'1'='1)", re.IGNORECASE),
    re.compile(r"(<script|javascript:|eval\(|base64_decode)", re.IGNORECASE),
]


def validate_honeypot_bind_host(host: str, allow_non_local: bool = False) -> str:
    """
    Validate bind host according to strict defensive isolation rules.
    Default bind MUST be 127.0.0.1. Rejects 0.0.0.0 and WAN addresses unless explicitly authorized.
    """
    clean_host = host.strip()
    if clean_host in ("127.0.0.1", "localhost", "::1"):
        return clean_host

    try:
        ip = ipaddress.ip_address(clean_host)
        if ip.is_loopback:
            return clean_host

        if ip.is_unspecified:  # 0.0.0.0
            if not allow_non_local:
                raise ScopeValidationError(
                    "Binding honeypot services to 0.0.0.0 is prohibited by default for safety. "
                    "Set HONEYPOT_ALLOW_NON_LOCAL=true in configuration to allow non-local binding."
                )
            return clean_host

        if ip.is_private:
            if not allow_non_local:
                raise ScopeValidationError(
                    f"Binding to LAN IP '{clean_host}' requires HONEYPOT_ALLOW_NON_LOCAL=true configuration."
                )
            return clean_host

        # Public WAN IP rejection
        raise ScopeValidationError(
            f"Binding honeypot to public WAN IP '{clean_host}' is strictly prohibited."
        )
    except ValueError as e:
        raise ScopeValidationError(f"Invalid honeypot bind host '{clean_host}': {e}")


def sanitize_honeypot_payload(raw_data: Any, max_len: int = 500) -> str:
    """
    Sanitize captured request payload to strictly strip and redact any credentials,
    passwords, auth tokens, session cookies, and API keys.
    """
    if raw_data is None:
        return ""

    if isinstance(raw_data, bytes):
        try:
            text = raw_data.decode("utf-8", errors="replace")
        except Exception:
            text = str(raw_data)
    else:
        text = str(raw_data)

    # Apply redactions
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)

    # Truncate
    clean = text.strip()
    if len(clean) > max_len:
        clean = clean[:max_len] + " ... [TRUNCATED]"

    return clean


def sanitize_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively scrub sensitive keys from metadata dictionaries."""
    sanitized = {}
    sensitive_keys = {"password", "passwd", "pwd", "secret", "token", "authorization", "cookie", "api_key", "credentials"}

    for k, v in meta.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_metadata(v)
        elif isinstance(v, list):
            sanitized[k] = [sanitize_metadata(i) if isinstance(i, dict) else sanitize_honeypot_payload(i) for i in v]
        elif isinstance(v, (str, bytes)):
            sanitized[k] = sanitize_honeypot_payload(v)
        else:
            sanitized[k] = v

    return sanitized


def classify_interaction(
    method: str = "GET",
    endpoint: str = "/",
    payload: str = "",
    protocol: str = "TCP",
    service_type: str = "HTTP",
) -> Tuple[str, Severity]:
    """
    Deterministically classify interaction type and assign appropriate severity.
    Does not automatically classify every connection as malicious.
    """
    ep_clean = (endpoint or "").strip().lower()
    method_clean = (method or "GET").strip().upper()
    svc = (service_type or "").strip().upper()

    # 1. Suspicious payload / injection check
    for susp_pattern in SUSPICIOUS_PATH_PATTERNS:
        if susp_pattern.search(ep_clean) or susp_pattern.search(payload or ""):
            return "suspicious_request", Severity.HIGH

    # 2. SSH Simulator
    if svc == "SSH" or protocol.upper() == "SSH":
        if "login" in payload.lower() or "auth" in payload.lower() or "password" in payload.lower():
            return "ssh_connection", Severity.MEDIUM
        return "ssh_connection", Severity.LOW

    # 3. Camera / RTSP Simulator
    if svc == "CAMERA" or "snapshot" in ep_clean or "stream" in ep_clean or "video" in ep_clean or "rtsp" in ep_clean:
        if method_clean == "POST":
            return "camera_access", Severity.MEDIUM
        return "camera_access", Severity.LOW

    # 4. HTTP Traps
    if ep_clean in ("/login", "/auth", "/api/login", "/api/auth", "/signin", "/session"):
        if method_clean == "POST":
            return "login_attempt", Severity.MEDIUM
        return "http_request", Severity.LOW

    if any(adm in ep_clean for adm in ("/admin", "/manage", "/setup", "/config", "/system", "/root")):
        if method_clean == "POST":
            return "admin_endpoint_access", Severity.HIGH
        return "admin_endpoint_access", Severity.MEDIUM

    if ep_clean in ("/status", "/device-info", "/info", "/version", "/metrics"):
        return "http_request", Severity.LOW

    if ep_clean in ("/", "/index.html", "/favicon.ico"):
        return "http_request", Severity.INFO

    return "http_request", Severity.INFO

