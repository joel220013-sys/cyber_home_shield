"""Integration tests for the /api/v1/scans endpoints."""

import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_16_post_scans_valid_target(async_client: AsyncClient):
    """Verify POST /api/v1/scans initiates discovery and returns 201 with ScanJobResponse."""
    payload = {
        "target_subnet": "192.168.1.0/24",
        "scan_type": "discovery",
        "dry_run": False,
        "ports": [22, 80, 443],
    }
    response = await async_client.post("/api/v1/scans", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["target_subnet"] == "192.168.1.0/24"
    assert data["status"] in ["RUNNING", "COMPLETED"]
    assert data["devices_found"] >= 0
    assert "id" in data


@pytest.mark.asyncio
async def test_17_get_scans_by_id(async_client: AsyncClient):
    """Verify GET /api/v1/scans/{id} retrieves scan job details."""
    # First create a scan
    payload = {
        "target_subnet": "10.0.0.0/24",
        "scan_type": "discovery",
    }
    create_res = await async_client.post("/api/v1/scans", json=payload)
    assert create_res.status_code == 201
    scan_id = create_res.json()["id"]

    # Now get the scan by ID
    get_res = await async_client.get(f"/api/v1/scans/{scan_id}")
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
        assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_get_scan_not_found(async_client: AsyncClient):
    """Verify GET /api/v1/scans/{id} returns 404 for non-existent ID."""
    random_id = str(uuid.uuid4())
    response = await async_client.get(f"/api/v1/scans/{random_id}")
    assert response.status_code == 404
