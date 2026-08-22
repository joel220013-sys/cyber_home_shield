"""Unit & Integration tests for Honeypot API Endpoints, IDOR, and Nemotron Analysis."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_honeypot_status_endpoint(async_client: AsyncClient):
    """Verify GET /api/v1/honeypot/status returns valid schema."""
    response = await async_client.get("/api/v1/honeypot/status")
    assert response.status_code == 200
    data = response.json()
    assert "services" in data
    assert "bind_host" in data
    assert len(data["services"]) == 3


@pytest.mark.asyncio
async def test_honeypot_start_stop_endpoints(async_client: AsyncClient):
    """Verify POST /api/v1/honeypot/start and POST /api/v1/honeypot/stop."""
    # 1. Start with localhost
    start_resp = await async_client.post("/api/v1/honeypot/start", json={"bind_host": "127.0.0.1"})
    assert start_resp.status_code == 200
    start_data = start_resp.json()
    assert start_data["running"] is True
    assert start_data["bind_host"] == "127.0.0.1"

    # 2. Stop
    stop_resp = await async_client.post("/api/v1/honeypot/stop")
    assert stop_resp.status_code == 200
    stop_data = stop_resp.json()
    assert stop_data["running"] is False


@pytest.mark.asyncio
async def test_honeypot_start_wan_rejection(async_client: AsyncClient):
    """Verify attempting to bind honeypot to a public WAN IP is rejected."""
    resp = await async_client.post("/api/v1/honeypot/start", json={"bind_host": "8.8.8.8"})
    assert resp.status_code == 400
    assert "strictly prohibited" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_honeypot_simulate_and_list_events(async_client: AsyncClient):
    """Verify POST /api/v1/honeypot/simulate creates event and GET /api/v1/honeypot/events lists it."""
    sim_resp = await async_client.post(
        "/api/v1/honeypot/simulate",
        json={
            "trap_type": "iot_gateway",
            "source_ip": "192.168.1.188",
            "interaction_type": "login_attempt",
            "endpoint": "/login",
        },
    )
    assert sim_resp.status_code == 201
    event_data = sim_resp.json()
    assert event_data["source_ip"] == "192.168.1.188"
    assert event_data["destination_port"] == 8088

    # List events
    list_resp = await async_client.get("/api/v1/honeypot/events")
    assert list_resp.status_code == 200
    events = list_resp.json()
    assert len(events) >= 1
    assert any(e["id"] == event_data["id"] for e in events)


@pytest.mark.asyncio
async def test_honeypot_analyze_endpoint(async_client: AsyncClient):
    """Verify POST /api/v1/honeypot/analyze/{id} returns Nemotron explanation."""
    # First simulate an event
    sim_resp = await async_client.post(
        "/api/v1/honeypot/simulate",
        json={
            "trap_type": "fake_ssh",
            "source_ip": "192.168.1.210",
            "interaction_type": "ssh_connection",
            "endpoint": "ssh",
        },
    )
    event_id = sim_resp.json()["id"]

    # Analyze
    analyze_resp = await async_client.post(f"/api/v1/honeypot/analyze/{event_id}")
    assert analyze_resp.status_code == 200
    analysis = analyze_resp.json()
    assert "summary" in analysis
    assert "pattern_detected" in analysis
    assert len(analysis["defensive_implications"]) > 0
    assert len(analysis["recommended_actions"]) > 0


@pytest.mark.asyncio
async def test_honeypot_event_idor_isolation(async_client: AsyncClient):
    """Verify User B cannot access or analyze User A's honeypot events (IDOR check)."""
    # 1. Register User A
    res_a = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "honeypot_a@home.local",
            "password": "PasswordUserA123!",
            "full_name": "Honeypot User A",
            "authorized_network_scope": "192.168.1.0/24",
        },
    )
    assert res_a.status_code == 201
    token_a = res_a.json()["access_token"]

    # 2. Register User B
    res_b = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "honeypot_b@home.local",
            "password": "PasswordUserB123!",
            "full_name": "Honeypot User B",
            "authorized_network_scope": "10.0.0.0/24",
        },
    )
    assert res_b.status_code == 201
    token_b = res_b.json()["access_token"]

    # 3. User A simulates a honeypot probe event
    sim_a = await async_client.post(
        "/api/v1/honeypot/simulate",
        json={
            "trap_type": "iot_gateway",
            "source_ip": "192.168.1.144",
            "interaction_type": "login_attempt",
            "endpoint": "/login",
        },
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert sim_a.status_code == 201
    event_id_a = sim_a.json()["id"]

    # 4. User A can retrieve their own event
    get_a = await async_client.get(
        f"/api/v1/honeypot/events/{event_id_a}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert get_a.status_code == 200

    # 5. User B attempts to access User A's event -> 404 (IDOR protected)
    get_b = await async_client.get(
        f"/api/v1/honeypot/events/{event_id_a}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert get_b.status_code == 404

    # 6. User B attempts to trigger Nemotron AI analysis on User A's event -> 404
    analyze_b = await async_client.post(
        f"/api/v1/honeypot/analyze/{event_id_a}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert analyze_b.status_code == 404
