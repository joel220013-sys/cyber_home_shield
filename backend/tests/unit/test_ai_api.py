"""API integration tests for AI Security Advisor endpoints."""

import json
import uuid
import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.device import Device
from app.models.enums import DeviceType, Severity
from app.models.open_port import OpenPort
from app.models.security_finding import SecurityFinding
from app.services.ai.service import ai_service


@pytest.mark.asyncio
async def test_23_post_ai_triage_endpoint(async_client: AsyncClient):
    """Verify POST /api/v1/ai/triage returns structured threat analysis."""
    payload = {
        "event_data": {"protocol": "TCP", "destination_port": 445},
        "finding_data": {"status": "normal", "anomaly_score": 15.0},
    }
    response = await async_client.post("/api/v1/ai/triage", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "analysis" in data
    assert "threat_detected" in data["analysis"]
    assert "confidence" in data["analysis"]
    assert "NVIDIA_API_KEY" not in str(data)  # No API key leakage


@pytest.mark.asyncio
async def test_24_post_ai_chat_endpoint(async_client: AsyncClient):
    """Verify POST /api/v1/ai/chat returns defensive advisory."""
    payload = {
        "message": "How do I secure my smart doorbell against local network snooping?",
        "history": [],
    }
    response = await async_client.post("/api/v1/ai/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    assert "suggested_followups" in data
    assert len(data["reply"]) > 10
    assert "NVIDIA_API_KEY" not in str(data)  # No secret leakage


@pytest.mark.asyncio
async def test_25_post_ai_hardening_guide_endpoint(async_client: AsyncClient):
    """Verify POST /api/v1/ai/hardening-guide returns actionable hardening steps."""
    payload = {
        "target_type": "ROUTER",
        "observed_services": [80, 445],
        "context": {"manufacturer": "Generic Router"},
    }
    response = await async_client.post("/api/v1/ai/hardening-guide", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "ROUTER"
    assert len(data["hardening_items"]) >= 1
    assert "action" in data["hardening_items"][0]
    assert "safe_steps" in data["hardening_items"][0]


@pytest.mark.asyncio
async def test_26_post_ai_explain_device_endpoint(async_client: AsyncClient, db_session):
    """Verify POST /api/v1/ai/explain-device/{id} explains device risk posture."""
    dev = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.100",
        mac_address="11:22:33:aa:bb:cc",
        hostname="iot-hub.home.arpa",
        device_type=DeviceType.IOT,
    )
    port = OpenPort(
        id=uuid.uuid4(),
        device_id=dev.id,
        port_number=80,
        protocol="TCP",
        service_name="http",
    )
    db_session.add(dev)
    db_session.add(port)
    await db_session.flush()

    response = await async_client.post(f"/api/v1/ai/explain-device/{dev.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["device_id"] == str(dev.id)
    assert "deterministic_risk_score" in data
    assert len(data["defensive_priorities"]) >= 1
    # Check that MAC address was not leaked in observations if present
    assert "11:22:33:aa:bb:cc" not in str(data.get("key_observations", []))


@pytest.mark.asyncio
async def test_27_post_ai_explain_finding_endpoint(async_client: AsyncClient, db_session):
    """Verify POST /api/v1/ai/explain-finding/{id} explains security finding."""
    dev = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.105",
        mac_address="22:33:44:aa:bb:cc",
        device_type=DeviceType.STORAGE,
    )
    finding = SecurityFinding(
        id=uuid.uuid4(),
        device_id=dev.id,
        title="Unencrypted SMB File Sharing",
        category="EXPOSURE",
        severity=Severity.HIGH,
        description="SMB service exposed on port 445 without encryption requirement.",
        remediation_steps="Disable SMBv1; Enable SMB encryption",
    )
    db_session.add(dev)
    db_session.add(finding)
    await db_session.flush()

    response = await async_client.post(f"/api/v1/ai/explain-finding/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Unencrypted SMB File Sharing"
    assert data["severity"] == "HIGH"
    assert len(data["remediation_steps"]) >= 1


@pytest.mark.asyncio
async def test_28_post_ai_explain_device_invalid_uuid(async_client: AsyncClient):
    """Verify POST /api/v1/ai/explain-device with invalid UUID returns 400."""
    response = await async_client.post("/api/v1/ai/explain-device/not-a-valid-uuid")
    assert response.status_code == 400
    assert "Invalid device UUID format" in response.json()["detail"]


@pytest.mark.asyncio
async def test_29_post_ai_explain_finding_invalid_uuid(async_client: AsyncClient):
    """Verify POST /api/v1/ai/explain-finding with invalid UUID returns 400."""
    response = await async_client.post("/api/v1/ai/explain-finding/not-a-valid-uuid")
    assert response.status_code == 400
    assert "Invalid finding UUID format" in response.json()["detail"]

