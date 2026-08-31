"""Integration tests for the /api/v1/scans endpoints."""

import uuid
import pytest
from httpx import AsyncClient
from app.models.user import User


@pytest.mark.asyncio
async def test_16_post_scans_valid_target(async_client: AsyncClient):
    """Verify POST /api/v1/scans initiates discovery and returns 201 with ScanJobResponse."""
    payload = {
        "target_subnet": "192.168.1.0/24",
        "scan_type": "discovery",
        "dry_run": False,
        "ports": [22, 80, 443],
    }
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scan-valid@home.local",
            "password": "ScanPassword123!",
            "full_name": "Scan User",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    response = await async_client.post("/api/v1/scans", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["target_subnet"] == "192.168.1.0/24"
    assert data["status"] in ["RUNNING", "COMPLETED"]
    assert data["devices_found"] >= 0
    assert "id" in data


@pytest.mark.asyncio
async def test_17_get_scans_by_id(async_client: AsyncClient):
    """Verify GET /api/v1/scans/{id} retrieves scan job details."""
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scan-detail-owner@home.local",
            "password": "ScanDetailPassword123!",
            "full_name": "Scan Detail Owner",
            "authorized_network_scope": "10.0.0.0/24",
        },
    )
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    # First create a scan
    payload = {
        "target_subnet": "10.0.0.0/24",
        "scan_type": "discovery",
    }
    create_res = await async_client.post("/api/v1/scans", json=payload, headers=headers)
    assert create_res.status_code == 201
    scan_id = create_res.json()["id"]

    # Now get the scan by ID
    get_res = await async_client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["id"] == scan_id
    assert data["target_subnet"] == "10.0.0.0/24"
    assert data["devices_found"] >= 0


@pytest.mark.asyncio
async def test_18_invalid_scan_target_rejected(async_client: AsyncClient):
    """Verify POST /api/v1/scans rejects public IP / unauthorized targets with 400 Bad Request."""
    invalid_payloads = [
        {"target_subnet": "8.8.8.8"},
        {"target_subnet": "127.0.0.1"},
        {"target_subnet": "224.0.0.1"},
        {"target_subnet": "invalid-cidr"},
    ]
    for payload in invalid_payloads:
        response = await async_client.post("/api/v1/scans", json=payload)
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_anonymous_scan_creation_rejected(async_client: AsyncClient):
    """Scan creation requires authentication before target processing."""
    response = await async_client.post(
        "/api/v1/scans",
        json={"target_subnet": "192.168.1.0/24", "dry_run": True},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_scan_not_found(async_client: AsyncClient):
    """Verify GET /api/v1/scans/{id} returns 404 for non-existent ID."""
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scan-detail-not-found@home.local",
            "password": "ScanDetailPassword123!",
            "full_name": "Scan Detail Not Found",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    random_id = str(uuid.uuid4())
    response = await async_client.get(f"/api/v1/scans/{random_id}", headers=headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_scan_target_must_fit_authenticated_user_scope(async_client: AsyncClient):
    """A scan target must be inside the authenticated user's stored CIDR."""
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scope-scan@home.local",
            "password": "ScopePassword123!",
            "full_name": "Scope Scanner",
            "authorized_network_scope": "192.168.10.0/24",
        },
    )
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}

    allowed = await async_client.post(
        "/api/v1/scans",
        json={"target_subnet": "192.168.10.0/24", "dry_run": True},
        headers=headers,
    )
    assert allowed.status_code == 201

    outside = await async_client.post(
        "/api/v1/scans",
        json={"target_subnet": "192.168.11.0/24", "dry_run": True},
        headers=headers,
    )
    assert outside.status_code == 400
    assert "authorized network scope" in outside.json()["detail"]

    public = await async_client.post(
        "/api/v1/scans",
        json={"target_subnet": "8.8.8.8", "dry_run": True},
        headers=headers,
    )
    assert public.status_code == 400


@pytest.mark.asyncio
async def test_scan_scope_cannot_be_borrowed_from_another_user(async_client: AsyncClient):
    """A user's server-side CIDR cannot be replaced by another user's scope."""
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scope-isolation@home.local",
            "password": "ScopePassword123!",
            "full_name": "Scope Isolation",
            "authorized_network_scope": "10.20.0.0/24",
        },
    )
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    response = await async_client.post(
        "/api/v1/scans",
        json={"target_subnet": "192.168.1.0/24", "dry_run": True},
        headers=headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_invalid_server_scope_is_rejected(async_client: AsyncClient, db_session):
    """An invalid scope loaded from persistence fails closed."""
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "invalid-server-scope@home.local",
            "password": "ScopePassword123!",
            "full_name": "Invalid Scope",
            "authorized_network_scope": "192.168.20.0/24",
        },
    )
    token = registration.json()["access_token"]
    user = await db_session.get(User, uuid.UUID(registration.json()["user"]["id"]))
    user.authorized_network_scope = "not-a-cidr"
    await db_session.flush()

    response = await async_client.post(
        "/api/v1/scans",
        json={"target_subnet": "192.168.20.0/24", "dry_run": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
