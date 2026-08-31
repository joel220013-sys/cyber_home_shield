"""Unit and integration tests for Authentication and User Profile API."""

import pytest
from httpx import AsyncClient
from datetime import timedelta
from app.core.security import create_access_token


@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient):
    """Test successful user registration with RFC 1918 network scope."""
    payload = {
        "email": "security_admin@home.local",
        "password": "SuperSecretPassword123!",
        "full_name": "Chief Security Officer",
        "authorized_network_scope": "192.168.10.0/24",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "security_admin@home.local"
    assert data["user"]["authorized_network_scope"] == "192.168.10.0/24"


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: AsyncClient):
    """Test registration fails with 400 when email already exists."""
    payload = {
        "email": "duplicate@home.local",
        "password": "Password12345!",
        "full_name": "User One",
        "authorized_network_scope": "192.168.1.0/24",
    }
    res1 = await async_client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = await async_client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_register_invalid_scope(async_client: AsyncClient):
    """Test registration rejects non-RFC 1918 public IP scopes."""
    payload = {
        "email": "attacker@fake.local",
        "password": "Password12345!",
        "full_name": "Public Scope Attempt",
        "authorized_network_scope": "8.8.8.0/24",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_short_password(async_client: AsyncClient):
    """Test registration rejects short passwords."""
    payload = {
        "email": "short@home.local",
        "password": "short",
        "full_name": "Short Pw",
        "authorized_network_scope": "192.168.1.0/24",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success_and_me(async_client: AsyncClient):
    """Test user login and fetching profile via /auth/me."""
    reg_payload = {
        "email": "analyst@home.local",
        "password": "ValidPassword999!",
        "full_name": "Security Analyst",
        "authorized_network_scope": "10.0.0.0/24",
    }
    await async_client.post("/api/v1/auth/register", json=reg_payload)

    # Login
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@home.local", "password": "ValidPassword999!"},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    token = login_data["access_token"]
    assert token

    # Get Me
    me_res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == "analyst@home.local"
    assert me_data["full_name"] == "Security Analyst"
    assert me_data["authorized_network_scope"] == "10.0.0.0/24"


@pytest.mark.asyncio
async def test_login_invalid_password(async_client: AsyncClient):
    """Test login with wrong password returns 401."""
    reg_payload = {
        "email": "user_pw_test@home.local",
        "password": "CorrectPassword123!",
    }
    await async_client.post("/api/v1/auth/register", json=reg_payload)

    res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "user_pw_test@home.local", "password": "WrongPassword123!"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_unauthorized(async_client: AsyncClient):
    """Test accessing protected /auth/me without token returns 401."""
    res = await async_client.get("/api/v1/auth/me")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_invalid_token(async_client: AsyncClient):
    """Test accessing /auth/me with invalid or tampered token returns 401."""
    res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.jwt.token"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_update_profile(async_client: AsyncClient):
    """Test updating user profile details and authorized scope."""
    reg_payload = {
        "email": "update_me@home.local",
        "password": "PasswordToUpdate123!",
        "full_name": "Original Name",
        "authorized_network_scope": "192.168.1.0/24",
    }
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    token = reg_res.json()["access_token"]

    update_res = await async_client.put(
        "/api/v1/auth/me",
        json={"full_name": "Updated Name", "authorized_network_scope": "172.16.50.0/24"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert update_res.status_code == 200
    updated_data = update_res.json()
    assert updated_data["full_name"] == "Updated Name"
    assert updated_data["authorized_network_scope"] == "172.16.50.0/24"


@pytest.mark.asyncio
async def test_logout(async_client: AsyncClient):
    """Test logout invalidates the logged-in token without affecting new sessions."""
    payload = {
        "email": "logout@home.local",
        "password": "LogoutPassword123!",
        "full_name": "Logout Test",
        "authorized_network_scope": "192.168.1.0/24",
    }
    await async_client.post("/api/v1/auth/register", json=payload)
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert (await async_client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    res = await async_client.post("/api/v1/auth/logout", headers=headers)
    assert res.status_code == 200
    assert "logged out" in res.json()["message"]
    assert (await async_client.get("/api/v1/auth/me", headers=headers)).status_code == 401

    new_login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": payload["email"], "password": payload["password"]},
    )
    assert new_login.status_code == 200
    new_headers = {"Authorization": f"Bearer {new_login.json()['access_token']}"}
    assert (await async_client.get("/api/v1/auth/me", headers=new_headers)).status_code == 200


@pytest.mark.asyncio
async def test_expired_token_remains_rejected(async_client: AsyncClient):
    """Token revocation must not weaken existing expiration rejection."""
    token = create_access_token("expired-user", expires_delta=timedelta(seconds=-1))
    response = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
