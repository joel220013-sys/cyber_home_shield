"""Unit and integration tests for the Security Findings API."""

import uuid

import pytest
from httpx import AsyncClient

from app.models.enums import FindingStatus, Severity
from app.models.security_finding import SecurityFinding


async def _register_user(
    async_client: AsyncClient,
    email: str,
    network_scope: str,
) -> str:
    response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "Password123!",
            "full_name": email,
            "authorized_network_scope": network_scope,
        },
    )
    assert response.status_code == 201
    return response.json()["access_token"]


async def _create_device(
    async_client: AsyncClient,
    token: str,
    ip_address: str,
) -> str:
    response = await async_client.post(
        "/api/v1/devices",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "ip_address": ip_address,
            "mac_address": f"AA:BB:CC:{uuid.uuid4().hex[:6].upper()}",
            "hostname": "test-device",
            "device_type": "IOT",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


@pytest.mark.asyncio
async def test_findings_are_authenticated_and_isolated(
    async_client: AsyncClient,
    db_session,
):
    """Users see their own findings, not another user's, and empty is valid."""
    token_a = await _register_user(
        async_client,
        "findings_a@home.local",
        "192.168.1.0/24",
    )
    token_b = await _register_user(
        async_client,
        "findings_b@home.local",
        "10.0.0.0/24",
    )
    token_empty = await _register_user(
        async_client,
        "findings_empty@home.local",
        "172.16.1.0/24",
    )

    device_a_id = await _create_device(async_client, token_a, "192.168.1.10")
    device_b_id = await _create_device(async_client, token_b, "10.0.0.10")

    db_session.add_all(
        [
            SecurityFinding(
                id=uuid.uuid4(),
                device_id=uuid.UUID(device_a_id),
                title="User A finding",
                category="Exposure",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                description="Finding owned by user A.",
                remediation_steps="Remediate user A finding.",
                cve_id="",
                evidence={"source": "test"},
            ),
            SecurityFinding(
                id=uuid.uuid4(),
                device_id=uuid.UUID(device_b_id),
                title="User B finding",
                category="Exposure",
                severity=Severity.MEDIUM,
                status=FindingStatus.OPEN,
                description="Finding owned by user B.",
                remediation_steps="Remediate user B finding.",
                cve_id="",
                evidence={"source": "test"},
            ),
            SecurityFinding(
                id=uuid.uuid4(),
                device_id=uuid.UUID(device_a_id),
                title="Resolved old finding",
                category="Exposure",
                severity=Severity.LOW,
                status=FindingStatus.RESOLVED,
                description="A stale finding.",
                remediation_steps="None.",
                cve_id="",
                evidence={"source": "test"},
            ),
        ]
    )
    await db_session.commit()

    findings_a = await async_client.get(
        "/api/v1/findings",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert findings_a.status_code == 200
    assert [item["title"] for item in findings_a.json()] == ["User A finding"]

    findings_b = await async_client.get(
        "/api/v1/findings",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert findings_b.status_code == 200
    assert [item["title"] for item in findings_b.json()] == ["User B finding"]

    findings_empty = await async_client.get(
        "/api/v1/findings",
        headers={"Authorization": f"Bearer {token_empty}"},
    )
    assert findings_empty.status_code == 200
    assert findings_empty.json() == []
