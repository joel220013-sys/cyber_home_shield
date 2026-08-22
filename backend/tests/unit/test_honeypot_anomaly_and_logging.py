"""Unit tests for Honeypot Anomaly Detection and DB Event Logging Integration."""

import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import Protocol, Severity
from app.models.honeypot_event import HoneypotEvent
from app.models.security_finding import SecurityFinding
from app.services.honeypot.base import HoneypotTelemetryEvent
from app.services.honeypot.event_logger import (
    HoneypotAnomalyTracker,
    log_honeypot_event,
)


def test_honeypot_anomaly_tracker_login_bruteforce():
    """Verify repeated login attempts (>= 5 in 60s) triggers anomaly."""
    tracker = HoneypotAnomalyTracker()
    source_ip = "192.168.1.200"
    now = datetime.now(timezone.utc)

    anomaly = None
    for _ in range(4):
        anomaly = tracker.record_and_evaluate(source_ip, "login_attempt", now)
        assert anomaly is None

    # 5th attempt triggers anomaly
    anomaly = tracker.record_and_evaluate(source_ip, "login_attempt", now)
    assert anomaly is not None
    assert anomaly["anomaly_type"] == "repeated_login_attempts"
    assert anomaly["severity"] == Severity.HIGH
    assert anomaly["count"] == 5


def test_honeypot_anomaly_tracker_admin_probe():
    """Verify repeated admin endpoint probing (>= 3 in 60s) triggers anomaly."""
    tracker = HoneypotAnomalyTracker()
    source_ip = "192.168.1.201"
    now = datetime.now(timezone.utc)

    assert tracker.record_and_evaluate(source_ip, "admin_endpoint_access", now) is None
    assert tracker.record_and_evaluate(source_ip, "admin_endpoint_access", now) is None

    # 3rd attempt
    anomaly = tracker.record_and_evaluate(source_ip, "admin_endpoint_access", now)
    assert anomaly is not None
    assert anomaly["anomaly_type"] == "repeated_admin_access"
    assert anomaly["severity"] == Severity.HIGH


@pytest.mark.asyncio
async def test_log_honeypot_event_persistence(db_session: AsyncSession):
    """Verify honeypot event is persisted to DB with sanitized metadata."""
    telemetry = HoneypotTelemetryEvent(
        honeypot_id="iot_gateway",
        source_ip="192.168.1.99",
        destination_ip="127.0.0.1",
        source_port=54321,
        destination_port=8088,
        protocol=Protocol.TCP,
        interaction_type="http_request",
        endpoint="/status",
        payload_sample="GET /status HTTP/1.1",
        metadata_fields={"probe": "inspection", "password": "SecretPassword!"},
        severity=Severity.INFO,
    )

    saved = await log_honeypot_event(db=db_session, telemetry=telemetry)
    assert saved.id is not None
    assert saved.source_ip == "192.168.1.99"
    assert saved.destination_port == 8088
    # Password in metadata must be redacted
    assert saved.metadata_fields.get("password") == "[REDACTED]"

    # Verify query
    query = select(HoneypotEvent).where(HoneypotEvent.id == saved.id)
    res = await db_session.execute(query)
    fetched = res.scalar_one_or_none()
    assert fetched is not None
    assert fetched.endpoint == "/status"

