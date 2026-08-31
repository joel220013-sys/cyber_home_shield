"""Unit tests verifying multi-tenancy data isolation and IDOR protection."""

import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_cross_tenant_device_idor_protection(async_client: AsyncClient):
    """
    Test that User B cannot access, read, or delete a private device owned by User A.
    """
    # 1. Register User A
    res_a = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "user_a@home.local",
            "password": "PasswordUserA123!",
            "full_name": "User A",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    assert res_a.status_code == 201
    token_a = res_a.json()["access_token"]

    # 2. Register User B
    res_b = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "user_b@home.local",
            "password": "PasswordUserB123!",
            "full_name": "User B",
            "authorized_network_scope": "10.0.0.0/24",
        },
    )
    assert res_b.status_code == 201
    token_b = res_b.json()["access_token"]

    # 3. User A creates a device
    dev_res = await async_client.post(
        "/api/v1/devices",
        json={
            "ip_address": "192.168.1.50",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "hostname": "UserA-Private-NAS",
            "device_type": "STORAGE",
            "custom_name": "Secure Storage Vault",
        },
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert dev_res.status_code == 201
    device_id = dev_res.json()["id"]

    # 4. User A can retrieve device
    get_a = await async_client.get(
        f"/api/v1/devices/{device_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert get_a.status_code == 200
    assert get_a.json()["hostname"] == "UserA-Private-NAS"

    # 5. User B attempts to retrieve User A's device (IDOR attempt -> 404)
    get_b = await async_client.get(
        f"/api/v1/devices/{device_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert get_b.status_code == 404

    # 6. User B attempts to delete User A's device (IDOR delete attempt -> 404)
    del_b = await async_client.delete(
        f"/api/v1/devices/{device_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert del_b.status_code == 404

    # 7. User B attempts to run AI risk explanation on User A's device (IDOR -> 404)
    explain_b = await async_client.post(
        f"/api/v1/ai/explain-device/{device_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert explain_b.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_scan_isolation(async_client: AsyncClient):
    """
    Test that User B cannot access scan jobs initiated by User A.
    """
    # 1. Register User A
    res_a = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scanner_a@home.local",
            "password": "PasswordUserA123!",
            "full_name": "Scanner User A",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    assert res_a.status_code == 201
    token_a = res_a.json()["access_token"]

    # 2. Register User B
    res_b = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "scanner_b@home.local",
            "password": "PasswordUserB123!",
            "full_name": "Scanner User B",
            "authorized_network_scope": "10.0.0.0/24",
        },
    )
    assert res_b.status_code == 201
    token_b = res_b.json()["access_token"]

    # 3. User A creates a scan
    scan_res = await async_client.post(
        "/api/v1/scans",
        json={
            "target_subnet": "192.168.1.100",
            "scan_type": "DISCOVERY",
            "dry_run": True,
        },
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert scan_res.status_code == 201
    scan_id = scan_res.json()["id"]

    # 4. User A can retrieve scan
    get_scan_a = await async_client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert get_scan_a.status_code == 200

    # 5. User B cannot retrieve User A's scan (IDOR check -> 404)
    get_scan_b = await async_client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert get_scan_b.status_code == 404


@pytest.mark.asyncio
async def test_device_enrollment_enforces_user_scope(async_client: AsyncClient):
    """Manual device enrollment must enforce the authenticated user's CIDR."""
    registration = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "device-scope@home.local",
            "password": "DeviceScope123!",
            "full_name": "Device Scope",
            "authorized_network_scope": "172.16.5.0/24",
        },
    )
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    payload = {
        "ip_address": "172.16.5.20",
        "mac_address": "AA:BB:CC:DD:EE:20",
        "hostname": "in-scope-device",
        "device_type": "IOT",
    }
    allowed = await async_client.post("/api/v1/devices", json=payload, headers=headers)
    assert allowed.status_code == 201

    outside = await async_client.post(
        "/api/v1/devices",
        json={**payload, "ip_address": "172.16.6.20", "mac_address": "AA:BB:CC:DD:EE:21"},
        headers=headers,
    )
    assert outside.status_code == 400

    public = await async_client.post(
        "/api/v1/devices",
        json={**payload, "ip_address": "8.8.8.8", "mac_address": "AA:BB:CC:DD:EE:22"},
        headers=headers,
    )
    assert public.status_code in (400, 422)


@pytest.mark.asyncio
async def test_anonymous_device_mutation_rejected(async_client: AsyncClient):
    """Device enrollment and deletion require an authenticated owner."""
    payload = {
        "ip_address": "192.168.1.230",
        "mac_address": "AA:BB:CC:DD:EE:30",
        "hostname": "private-device",
        "device_type": "IOT",
    }
    create_response = await async_client.post("/api/v1/devices", json=payload)
    assert create_response.status_code == 401
    assert (await async_client.delete(f"/api/v1/devices/{uuid.uuid4()}")).status_code == 401
