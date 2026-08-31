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


async def _ai_auth_headers(client: AsyncClient, email: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "AiTestPassword123!",
            "full_name": "AI Test User",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.mark.asyncio
async def test_general_ai_endpoints_reject_anonymous(async_client: AsyncClient):
    """Provider-forwarding AI endpoints require authentication."""
    assert (await async_client.post("/api/v1/ai/triage", json={})).status_code == 401
    assert (await async_client.post("/api/v1/ai/chat", json={"message": "help"})).status_code == 401
    assert (
        await async_client.post(
            "/api/v1/ai/hardening-guide",
            json={"target_type": "IOT"},
        )
    ).status_code == 401


@pytest.mark.asyncio
async def test_23_post_ai_triage_endpoint(async_client: AsyncClient):
    """Verify POST /api/v1/ai/triage returns structured threat analysis."""
    payload = {
        "event_data": {"protocol": "TCP", "destination_port": 445},
        "finding_data": {"status": "normal", "anomaly_score": 15.0},
    }
    headers = await _ai_auth_headers(async_client, "ai-triage@home.local")
    response = await async_client.post("/api/v1/ai/triage", json=payload, headers=headers)
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
    headers = await _ai_auth_headers(async_client, "ai-chat@home.local")
    response = await async_client.post("/api/v1/ai/chat", json=payload, headers=headers)
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
    headers = await _ai_auth_headers(async_client, "ai-hardening@home.local")
    response = await async_client.post("/api/v1/ai/hardening-guide", json=payload, headers=headers)
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

    headers = await _ai_auth_headers(async_client, "ai-device@home.local")
    response = await async_client.post(f"/api/v1/ai/explain-device/{dev.id}", headers=headers)
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

    headers = await _ai_auth_headers(async_client, "ai-finding@home.local")
    response = await async_client.post(f"/api/v1/ai/explain-finding/{finding.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Unencrypted SMB File Sharing"
    assert data["severity"] == "HIGH"
    assert len(data["remediation_steps"]) >= 1


@pytest.mark.asyncio
async def test_28_post_ai_explain_device_invalid_uuid(async_client: AsyncClient):
    """Verify POST /api/v1/ai/explain-device with invalid UUID returns 400."""
    headers = await _ai_auth_headers(async_client, "ai-invalid-device@home.local")
    response = await async_client.post("/api/v1/ai/explain-device/not-a-valid-uuid", headers=headers)
    assert response.status_code == 400
    assert "Invalid device UUID format" in response.json()["detail"]


@pytest.mark.asyncio
async def test_29_post_ai_explain_finding_invalid_uuid(async_client: AsyncClient):
    """Verify POST /api/v1/ai/explain-finding with invalid UUID returns 400."""
    headers = await _ai_auth_headers(async_client, "ai-invalid-finding@home.local")
    response = await async_client.post("/api/v1/ai/explain-finding/not-a-valid-uuid", headers=headers)
    assert response.status_code == 400
    assert "Invalid finding UUID format" in response.json()["detail"]


@pytest.mark.asyncio
async def test_ai_device_resource_requires_owner(
    async_client: AsyncClient,
    db_session,
):
    """Verify anonymous and cross-user device explanations are rejected."""
    owner_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "ai-owner@home.local",
            "password": "PasswordOwner123!",
            "full_name": "AI Owner",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    other_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "ai-other@home.local",
            "password": "PasswordOther123!",
            "full_name": "AI Other",
            "authorized_network_scope": "10.0.0.0/24",
        },
    )
    owner_token = owner_response.json()["access_token"]
    other_token = other_response.json()["access_token"]
    owner_id = uuid.UUID(owner_response.json()["user"]["id"])

    device = Device(
        id=uuid.uuid4(),
        user_id=owner_id,
        ip_address="192.168.1.120",
        mac_address="33:44:55:aa:bb:cc",
        device_type=DeviceType.IOT,
    )
    db_session.add(device)
    await db_session.flush()

    endpoint = f"/api/v1/ai/explain-device/{device.id}"
    assert (await async_client.post(endpoint)).status_code == 404
    assert (await async_client.post(endpoint, headers={"Authorization": f"Bearer {other_token}"})).status_code == 404

    chat_payload = {
        "message": "Explain this device.",
        "context_device_id": str(device.id),
        "history": [],
    }
    assert (await async_client.post("/api/v1/ai/chat", json=chat_payload)).status_code == 401
    assert (
        await async_client.post(
            "/api/v1/ai/chat",
            json=chat_payload,
            headers={"Authorization": f"Bearer {other_token}"},
        )
    ).status_code == 404

    fallback_response = {
        "device_id": str(device.id),
        "deterministic_risk_score": 0.0,
        "key_observations": [],
        "risk_factors_explained": [],
        "likely_security_implications": "No immediate exposure observed.",
        "defensive_priorities": ["Continue monitoring"],
        "ai_available": False,
    }
    with patch.object(ai_service, "explain_device", new=AsyncMock(return_value=fallback_response)):
        response = await async_client.post(
            endpoint,
            headers={"Authorization": f"Bearer {owner_token}"},
        )
    assert response.status_code == 200
    assert response.json()["ai_available"] is False


@pytest.mark.asyncio
async def test_ai_finding_resource_requires_owner(
    async_client: AsyncClient,
    db_session,
):
    """Verify anonymous and cross-user finding explanations are rejected."""
    owner_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "finding-owner@home.local",
            "password": "PasswordOwner123!",
            "full_name": "Finding Owner",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    other_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "finding-other@home.local",
            "password": "PasswordOther123!",
            "full_name": "Finding Other",
            "authorized_network_scope": "10.0.0.0/24",
        },
    )
    owner_token = owner_response.json()["access_token"]
    other_token = other_response.json()["access_token"]
    owner_id = uuid.UUID(owner_response.json()["user"]["id"])

    device = Device(
        id=uuid.uuid4(),
        user_id=owner_id,
        ip_address="192.168.1.121",
        mac_address="44:55:66:aa:bb:cc",
        device_type=DeviceType.STORAGE,
    )
    finding = SecurityFinding(
        id=uuid.uuid4(),
        device_id=device.id,
        title="Owned finding",
        category="EXPOSURE",
        severity=Severity.HIGH,
        description="Owned finding description",
        remediation_steps="Remediate the owned finding",
    )
    db_session.add_all([device, finding])
    await db_session.flush()

    endpoint = f"/api/v1/ai/explain-finding/{finding.id}"
    assert (await async_client.post(endpoint)).status_code == 404
    assert (await async_client.post(endpoint, headers={"Authorization": f"Bearer {other_token}"})).status_code == 404

    fallback_response = {
        "title": finding.title,
        "severity": "HIGH",
        "explanation": "Owned finding requires remediation.",
        "potential_impact": "Potential exposure.",
        "observed_facts": [],
        "inferred_risks": [],
        "defensive_recommendations": ["Remediate"],
        "remediation_steps": ["Remediate the owned finding"],
        "cve_context": "No CVE confirmed.",
        "ai_available": False,
    }
    with patch.object(ai_service, "explain_finding", new=AsyncMock(return_value=fallback_response)):
        response = await async_client.post(
            endpoint,
            headers={"Authorization": f"Bearer {owner_token}"},
        )
    assert response.status_code == 200
    assert response.json()["ai_available"] is False

