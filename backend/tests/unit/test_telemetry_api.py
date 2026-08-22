"""Tests for authenticated network telemetry reads."""

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from httpx import AsyncClient

from app.models.enums import Protocol, Severity
from app.models.network_event import NetworkEvent


@pytest.mark.asyncio
async def test_telemetry_events_require_authentication(async_client: AsyncClient):
    response = await async_client.get("/api/v1/telemetry/events")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_telemetry_events_return_empty_list_for_user_without_events(
    async_client: AsyncClient,
):
    register_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "telemetry-empty@home.local",
            "password": "TelemetryPassword123!",
            "full_name": "Telemetry Empty",
        },
    )
    token = register_response.json()["access_token"]

    response = await async_client.get(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_telemetry_events_are_isolated_and_newest_first(
    async_client: AsyncClient,
    db_session,
):
    register_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "telemetry-reader@home.local",
            "password": "TelemetryPassword123!",
            "full_name": "Telemetry Reader",
        },
    )
    assert register_response.status_code == 201
    register_data = register_response.json()
    token = register_data["access_token"]
    user_id = uuid.UUID(register_data["user"]["id"])

    other_register_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "telemetry-other@home.local",
            "password": "TelemetryPassword123!",
            "full_name": "Telemetry Other",
        },
    )
    assert other_register_response.status_code == 201
    other_user_id = uuid.UUID(other_register_response.json()["user"]["id"])

    now = datetime.now(timezone.utc)
    own_old = NetworkEvent(
        user_id=user_id,
        event_timestamp=now - timedelta(minutes=1),
        source_ip="10.0.0.2",
        destination_ip="10.0.0.1",
        destination_port=443,
        protocol=Protocol.TCP,
        severity=Severity.INFO,
    )
    own_new = NetworkEvent(
        user_id=user_id,
        event_timestamp=now,
        source_ip="10.0.0.2",
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol=Protocol.TCP,
        severity=Severity.LOW,
    )
    other = NetworkEvent(
        user_id=other_user_id,
        event_timestamp=now + timedelta(minutes=1),
        source_ip="10.0.0.3",
        destination_ip="10.0.0.1",
        destination_port=22,
        protocol=Protocol.TCP,
        severity=Severity.HIGH,
    )
    db_session.add_all([own_old, own_new, other])
    await db_session.commit()

    response = await async_client.get(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert [event["destination_port"] for event in data] == [80, 443]