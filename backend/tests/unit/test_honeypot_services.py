"""Unit tests for Honeypot Trap Services (HTTP, SSH, Camera)."""

import pytest
from app.models.enums import Protocol, Severity
from app.services.honeypot.base import HoneypotTelemetryEvent
from app.services.honeypot.services.http_trap import HttpIoTGatewayTrap
from app.services.honeypot.services.iot_trap import CameraDecoyTrap
from app.services.honeypot.services.ssh_trap import SshDecoyTrap
from app.services.honeypot.manager import HoneypotManager


@pytest.mark.asyncio
async def test_http_trap_interaction_handling():
    """Verify HTTP decoy trap produces safe responses and logs telemetry."""
    events = []
    trap = HttpIoTGatewayTrap(
        port=8088,
        bind_host="127.0.0.1",
        on_event_callback=lambda e: events.append(e),
    )

    # 1. Test status page
    res_status = await trap.handle_simulated_interaction(
        source_ip="192.168.1.150",
        method="GET",
        endpoint="/status",
    )
    assert res_status["status_code"] == 200
    assert "active" in res_status["response_body"]
    assert trap.interaction_count == 1

    # 2. Test login attempt
    res_login = await trap.handle_simulated_interaction(
        source_ip="192.168.1.150",
        method="POST",
        endpoint="/login",
        payload="user=admin&password=SuperSecret!",
    )
    assert res_login["status_code"] == 401
    assert res_login["interaction_type"] == "login_attempt"
    assert res_login["severity"] == Severity.MEDIUM
    assert trap.interaction_count == 2

    # Check that captured event has sanitized payload
    last_event: HoneypotTelemetryEvent = events[-1]
    assert "SuperSecret!" not in last_event.payload_sample
    assert "[REDACTED]" in last_event.payload_sample
    assert last_event.destination_port == 8088


@pytest.mark.asyncio
async def test_ssh_trap_interaction_handling():
    """Verify SSH decoy trap emits simulated banner and records telemetry without shell execution."""
    events = []
    trap = SshDecoyTrap(
        port=2222,
        bind_host="127.0.0.1",
        on_event_callback=lambda e: events.append(e),
    )

    res = await trap.handle_simulated_interaction(
        source_ip="192.168.1.175",
        method="CONNECT",
        endpoint="ssh",
        payload="SSH-2.0-OpenSSH_8.2p1",
    )

    assert "SSH-2.0-CyberHomeShield-Simulated" in res["response_body"]
    assert res["interaction_type"] == "ssh_connection"
    assert trap.interaction_count == 1

    assert len(events) == 1
    assert events[0].protocol == Protocol.TCP
    assert events[0].destination_port == 2222


@pytest.mark.asyncio
async def test_camera_trap_interaction_handling():
    """Verify Camera decoy trap handles snapshot and stream inquiries safely."""
    events = []
    trap = CameraDecoyTrap(
        port=8554,
        bind_host="127.0.0.1",
        on_event_callback=lambda e: events.append(e),
    )

    res = await trap.handle_simulated_interaction(
        source_ip="192.168.1.180",
        method="GET",
        endpoint="/snapshot",
    )

    assert res["status_code"] == 503
    assert "unavailable" in res["response_body"]
    assert res["interaction_type"] == "camera_access"
    assert trap.interaction_count == 1


@pytest.mark.asyncio
async def test_http_frontend_trap_identifier_routes_to_real_http_trap():
    """Verify the frontend HTTP identifier selects the registered HTTP trap."""
    manager = HoneypotManager()

    event = await manager.handle_simulated_probe(
        trap_type="http_iot_gateway",
        source_ip="192.168.1.188",
    )

    assert event.honeypot_id == "iot_gateway"
    assert event.destination_port == 8088



