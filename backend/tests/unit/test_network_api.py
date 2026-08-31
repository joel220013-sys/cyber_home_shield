"""Tests for authenticated, read-only local network detection."""

from unittest.mock import patch
import uuid

import pytest
from httpx import AsyncClient

from app.schemas.network import RouterDetectionResponse
from app.schemas.network_health import RouterHealthResponse
from app.services.network import LocalNetworkDetector
from app.services.discovery.models import DiscoveryResult, DiscoveredHost, DiscoveredService
from app.models.device import Device
from app.models.security_finding import SecurityFinding
from app.models.network_event import NetworkEvent
from app.models.honeypot_event import HoneypotEvent
from app.models.enums import FindingStatus, Severity


async def _headers(
    client: AsyncClient,
    authorized_network_scope: str = "192.168.1.0/24",
) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "network-test@home.local",
            "password": "NetworkPassword123!",
            "full_name": "Network Test",
            "authorized_network_scope": authorized_network_scope,
        },
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.mark.asyncio
async def test_router_detection_requires_authentication(async_client: AsyncClient):
    response = await async_client.get("/api/v1/network/router")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_router_detection_returns_detected_response(async_client: AsyncClient):
    headers = await _headers(async_client)
    detected = RouterDetectionResponse(
        status="detected",
        gateway_ip="192.168.1.1",
        local_ip="192.168.1.23",
        network_cidr="192.168.1.0/24",
        interface="Wi-Fi",
        connection_type="wifi",
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detected):
        response = await async_client.get("/api/v1/network/router", headers=headers)

    assert response.status_code == 200
    assert response.json() == detected.model_dump()
    assert "password" not in response.text.lower()
    assert "secret" not in response.text.lower()
    assert "token" not in response.text.lower()


@pytest.mark.asyncio
async def test_router_detection_unavailable_is_safe(async_client: AsyncClient):
    headers = await _headers(async_client)
    unavailable = RouterDetectionResponse(status="unavailable")
    with patch.object(LocalNetworkDetector, "detect", return_value=unavailable):
        response = await async_client.get("/api/v1/network/router", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "status": "unavailable",
        "gateway_ip": None,
        "local_ip": None,
        "network_cidr": None,
        "interface": None,
        "connection_type": None,
        "dhcp_server_ip": None,
        "dns_server_ips": [],
        "evidence": [],
    }


def test_malformed_interface_data_fails_closed():
    output = "Ethernet adapter Wi-Fi:\n   IPv4 Address. . . . . . : 192.168.1.23\n   Subnet Mask . . . . . . : malformed"
    local_ip, cidr, connection_type, dhcp, dns_servers = LocalNetworkDetector._parse_windows_interface(
        output,
        "192.168.1.1",
        "192.168.1.23",
    )
    assert (local_ip, cidr, connection_type, dhcp, dns_servers) == (None, None, None, None, [])


def test_windows_interface_name_is_not_an_ip():
    output = (
        "Ethernet adapter Ethernet:\n"
        "   IPv4 Address. . . . . . : 192.168.1.23\n"
        "   Subnet Mask . . . . . . : 255.255.255.0"
    )
    local_ip, cidr, connection_type, dhcp, dns_servers = LocalNetworkDetector._parse_windows_interface(
        output,
        "192.168.1.1",
        "192.168.1.23",
    )
    assert local_ip == "192.168.1.23"
    assert cidr == "192.168.1.0/24"
    assert connection_type == "ethernet"
    assert dhcp is None
    assert dns_servers == []


def test_windows_split_adapter_header_is_detected():
    output = (
        "Ethernet adapter Ethernet:\n\n"
        "   IPv4 Address. . . . . . : 192.168.1.23(Preferred)\n"
        "   Subnet Mask . . . . . . : 255.255.255.0"
    )
    local_ip, cidr, connection_type, dhcp, dns_servers = LocalNetworkDetector._parse_windows_interface(
        output,
        "192.168.1.1",
        "192.168.1.23",
    )
    assert (local_ip, cidr, connection_type) == (
        "192.168.1.23",
        "192.168.1.0/24",
        "ethernet",
    )
    assert LocalNetworkDetector._parse_windows_adapter_name(
        output,
        "192.168.1.23",
    ) == "Ethernet"


def test_windows_interface_collects_dhcp_and_dns_evidence():
    output = (
        "Ethernet adapter Ethernet:\n\n"
        "   IPv4 Address. . . . . . : 192.168.1.23(Preferred)\n"
        "   Subnet Mask . . . . . . : 255.255.255.0\n"
        "   DHCP Server . . . . . . : 192.168.1.1\n"
        "   DNS Servers . . . . . . : 192.168.1.1\n"
        "                                       1.1.1.1"
    )
    _, _, _, dhcp, dns_servers = LocalNetworkDetector._parse_windows_interface(
        output, "192.168.1.1", "192.168.1.23"
    )
    assert dhcp == "192.168.1.1"
    assert dns_servers == ["192.168.1.1", "1.1.1.1"]


def test_windows_adapter_name_uses_nearest_header():
    output = (
        "Wireless LAN adapter Wi-Fi:\n\n"
        "   IPv4 Address. . . . . . : 192.168.1.20\n\n"
        "Ethernet adapter Ethernet:\n\n"
        "   IPv4 Address. . . . . . : 192.168.1.23(Preferred)\n"
        "   Subnet Mask . . . . . . : 255.255.255.0"
    )
    assert LocalNetworkDetector._parse_windows_adapter_name(
        output,
        "192.168.1.23",
    ) == "Ethernet"


def test_public_gateway_fails_closed():
    gateway, interface = LocalNetworkDetector._parse_windows_route(
        "  0.0.0.0          0.0.0.0       8.8.8.8       192.168.1.23     25"
    )
    assert gateway is None
    assert interface is None


@pytest.mark.asyncio
async def test_router_health_requires_authentication(async_client: AsyncClient):
    response = await async_client.get("/api/v1/network/router/health")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_router_health_returns_reachable_gateway(async_client: AsyncClient):
    headers = await _headers(async_client)
    detection = RouterDetectionResponse(
        status="detected",
        gateway_ip="192.168.1.1",
        local_ip="192.168.1.23",
        network_cidr="192.168.1.0/24",
        interface="Ethernet",
        connection_type="ethernet",
    )
    health = RouterHealthResponse(
        status="reachable",
        gateway_ip="192.168.1.1",
        latency_ms=4.2,
        checked_at="2026-08-24T00:00:00Z",
        method="icmp_ping",
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.services.network.subprocess.run",
        return_value=type("Result", (), {"returncode": 0})(),
    ):
        response = await async_client.get("/api/v1/network/router/health", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "reachable"
    assert data["gateway_ip"] == "192.168.1.1"
    assert data["method"] == "icmp_ping"


@pytest.mark.asyncio
async def test_router_health_unavailable_gateway_is_safe(async_client: AsyncClient):
    headers = await _headers(async_client)
    with patch.object(
        LocalNetworkDetector,
        "detect",
        return_value=RouterDetectionResponse(status="unavailable"),
    ):
        response = await async_client.get("/api/v1/network/router/health", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"
    assert response.json()["latency_ms"] is None
    assert response.json()["method"] is None


@pytest.mark.asyncio
async def test_router_health_rejects_public_gateway(async_client: AsyncClient):
    headers = await _headers(async_client)
    detection = RouterDetectionResponse(status="detected", gateway_ip="8.8.8.8")
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.services.network.subprocess.run"
    ) as run:
        response = await async_client.get("/api/v1/network/router/health", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"
    run.assert_not_called()


@pytest.mark.asyncio
async def test_router_health_has_no_target_parameter(async_client: AsyncClient):
    headers = await _headers(async_client)
    response = await async_client.get(
        "/api/v1/network/router/health?target=192.168.1.99",
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["gateway_ip"] != "192.168.1.99"


@pytest.mark.asyncio
async def test_router_health_timeout_returns_unavailable(async_client: AsyncClient):
    headers = await _headers(async_client)
    detection = RouterDetectionResponse(status="detected", gateway_ip="192.168.1.1")
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.services.network.subprocess.run",
        side_effect=TimeoutError(),
    ):
        response = await async_client.get("/api/v1/network/router/health", headers=headers)

    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"


@pytest.mark.asyncio
async def test_network_discovery_requires_authentication(async_client: AsyncClient):
    response = await async_client.post("/api/v1/network/devices/discover", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_network_discovery_uses_detected_authorized_cidr(async_client: AsyncClient, db_session):
    headers = await _headers(async_client)
    detection = RouterDetectionResponse(
        status="detected",
        gateway_ip="192.168.1.1",
        local_ip="192.168.1.23",
        network_cidr="192.168.1.0/24",
        interface="Ethernet",
        connection_type="ethernet",
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(
        target="192.168.1.0/24",
        started_at=now,
        completed_at=now,
        hosts=[DiscoveredHost(ip_address="192.168.1.44", mac_address="00:BB:CC:DD:EE:44", hostname="cam.local")],
        services=[],
        evidence=[],
        errors=[],
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.api.v1.endpoints.network.DiscoveryService.execute_discovery",
        return_value=(result, None),
    ) as execute:
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )

    assert response.status_code == 200
    data = response.json()
    assert data["network"] == "192.168.1.0/24"
    device = data["devices"][0]
    assert device["hostname"] == "cam.local"
    assert device["identity_classification"] == "KNOWN"
    assert device["device_role"] == "Unknown"
    assert device["reason"] == "No suspicious security evidence observed"
    assert any(item["category"] == "reachability" for item in device["posture_evidence"])
    execute.assert_awaited_once()
    assert execute.await_args.kwargs["target_str"] == "192.168.1.0/24"
    assert execute.await_args.kwargs["local_ip"] == "192.168.1.23"


@pytest.mark.asyncio
async def test_network_discovery_preserves_privacy_mac_label(async_client: AsyncClient):
    headers = await _headers(async_client, "10.57.15.0/24")
    detection = RouterDetectionResponse(
        status="detected",
        local_ip="10.57.15.139",
        network_cidr="10.57.15.0/24",
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(
        target="10.57.15.0/24",
        started_at=now,
        completed_at=now,
        hosts=[DiscoveredHost(
            ip_address="10.57.15.102",
            mac_address="2E:C5:4F:A9:7D:1A",
        )],
        services=[],
        evidence=[],
        errors=[],
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.api.v1.endpoints.network.DiscoveryService.execute_discovery",
        return_value=(result, None),
    ):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )

    assert response.status_code == 200
    assert response.json()["devices"][0]["vendor"] is None
    assert response.json()["devices"][0]["mac_type"] == "locally_administered"


@pytest.mark.asyncio
async def test_network_discovery_keeps_unidentified_device(async_client: AsyncClient):
    headers = await _headers(async_client, "10.57.15.0/24")
    detection = RouterDetectionResponse(
        status="detected",
        local_ip="10.57.15.139",
        network_cidr="10.57.15.0/24",
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(
        target="10.57.15.0/24",
        started_at=now,
        completed_at=now,
        hosts=[DiscoveredHost(
            ip_address="10.57.15.130",
            mac_address="2E:C5:4F:A9:7D:1A",
        )],
        services=[],
        evidence=[],
        errors=[],
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.api.v1.endpoints.network.DiscoveryService.execute_discovery",
        return_value=(result, None),
    ):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )

    device = response.json()["devices"][0]
    assert device["classification"] == "UNIDENTIFIED"
    assert device["evidence_state"] == "Hostname unavailable; checked local resolver sources returned no result"


@pytest.mark.asyncio
async def test_network_discovery_open_service_alone_is_not_suspicious(async_client: AsyncClient):
    headers = await _headers(async_client, "10.57.15.0/24")
    detection = RouterDetectionResponse(
        status="detected",
        local_ip="10.57.15.139",
        network_cidr="10.57.15.0/24",
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(
        target="10.57.15.0/24",
        started_at=now,
        completed_at=now,
        hosts=[DiscoveredHost(
            ip_address="10.57.15.41",
            mac_address="00:E1:15:74:86:E4",
            services=[DiscoveredService(port=443, state="open")],
        )],
        services=[],
        evidence=[],
        errors=[],
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.api.v1.endpoints.network.DiscoveryService.execute_discovery",
        return_value=(result, None),
    ):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )

    assert response.json()["devices"][0]["identity_classification"] == "UNIDENTIFIED"


@pytest.mark.asyncio
async def test_network_discovery_active_finding_is_suspicious(
    async_client: AsyncClient,
    db_session,
):
    headers = await _headers(async_client, "10.57.15.0/24")
    user_id = uuid.UUID((await async_client.get("/api/v1/auth/me", headers=headers)).json()["id"])
    device_id = uuid.uuid4()
    db_session.add(Device(
        id=device_id,
        user_id=user_id,
        ip_address="10.57.15.41",
        mac_address="00:E1:15:74:86:E4",
    ))
    db_session.add(SecurityFinding(
        id=uuid.uuid4(),
        device_id=device_id,
        title="Credential probing observed",
        category="AUTHENTICATION",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        description="Repeated credential probing event observed.",
        evidence={"source": "honeypot", "interaction": "login_attempt"},
    ))
    await db_session.commit()

    detection = RouterDetectionResponse(
        status="detected",
        gateway_ip="10.57.15.41",
        local_ip="10.57.15.139",
        network_cidr="10.57.15.0/24",
    )
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(
        target="10.57.15.0/24",
        started_at=now,
        completed_at=now,
        hosts=[DiscoveredHost(
            ip_address="10.57.15.41",
            mac_address="00:E1:15:74:86:E4",
        )],
        services=[],
        evidence=[],
        errors=[],
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.api.v1.endpoints.network.DiscoveryService.execute_discovery",
        return_value=(result, None),
    ):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )

    device = response.json()["devices"][0]
    assert device["identity_classification"] == "SUSPICIOUS"
    assert "active security finding: Credential probing observed" in device["evidence"]
    assert device["reason"] == "Security-relevant evidence observed"


@pytest.mark.asyncio
async def test_network_discovery_gateway_role_comes_from_default_route(async_client: AsyncClient):
    headers = await _headers(async_client, "10.57.15.0/24")
    detection = RouterDetectionResponse(status="detected", gateway_ip="10.57.15.1", local_ip="10.57.15.139", network_cidr="10.57.15.0/24")
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(target="10.57.15.0/24", started_at=now, completed_at=now, hosts=[DiscoveredHost(ip_address="10.57.15.1", mac_address="00:E1:15:74:86:E4")], services=[], evidence=[], errors=[])
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch("app.api.v1.endpoints.network.DiscoveryService.execute_discovery", return_value=(result, None)):
        response = await async_client.post("/api/v1/network/devices/discover", json={}, headers=headers)
    device = response.json()["devices"][0]
    assert device["device_role"] == "Gateway/Router"
    assert {item["source"] for item in device["posture_evidence"]} >= {"default_gateway_route"}


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["anomaly", "honeypot"])
async def test_network_discovery_telemetry_and_honeypot_signals_are_suspicious(async_client: AsyncClient, db_session, signal: str):
    headers = await _headers(async_client, "10.57.15.0/24")
    user_id = uuid.UUID((await async_client.get("/api/v1/auth/me", headers=headers)).json()["id"])
    device_id = uuid.uuid4()
    db_session.add(Device(id=device_id, user_id=user_id, ip_address="10.57.15.41", mac_address="00:E1:15:74:86:E4"))
    if signal == "anomaly":
        db_session.add(NetworkEvent(device_id=device_id, user_id=user_id, source_ip="10.57.15.41", destination_ip="10.57.15.1", destination_port=53, is_anomaly=True, anomaly_reason="Unexpected DNS burst"))
    else:
        db_session.add(HoneypotEvent(user_id=user_id, source_ip="10.57.15.41", destination_port=8088, interaction_type="credential_probe"))
    await db_session.commit()
    detection = RouterDetectionResponse(status="detected", local_ip="10.57.15.139", network_cidr="10.57.15.0/24")
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    result = DiscoveryResult(target="10.57.15.0/24", started_at=now, completed_at=now, hosts=[DiscoveredHost(ip_address="10.57.15.41", mac_address="00:E1:15:74:86:E4")], services=[], evidence=[], errors=[])
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch("app.api.v1.endpoints.network.DiscoveryService.execute_discovery", return_value=(result, None)):
        response = await async_client.post("/api/v1/network/devices/discover", json={}, headers=headers)
    device = response.json()["devices"][0]
    assert device["identity_classification"] == "SUSPICIOUS"
    assert any(item["source"] == ("anomalous_telemetry" if signal == "anomaly" else "honeypot_interaction") for item in device["posture_evidence"])


@pytest.mark.asyncio
async def test_network_discovery_unavailable_and_out_of_scope_are_safe(async_client: AsyncClient):
    headers = await _headers(async_client)
    with patch.object(
        LocalNetworkDetector,
        "detect",
        return_value=RouterDetectionResponse(status="unavailable"),
    ):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )
    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"

    invalid_target = await async_client.post(
        "/api/v1/network/devices/discover",
        json={"target_subnet": "192.168.1.0/24"},
        headers=headers,
    )
    assert invalid_target.status_code == 422

    detection = RouterDetectionResponse(status="detected", network_cidr="10.0.0.0/24")
    with patch.object(LocalNetworkDetector, "detect", return_value=detection):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )
    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"


@pytest.mark.asyncio
async def test_network_discovery_timeout_returns_safe_unavailable(async_client: AsyncClient):
    headers = await _headers(async_client)
    detection = RouterDetectionResponse(
        status="detected",
        gateway_ip="192.168.1.1",
        network_cidr="192.168.1.0/24",
    )
    with patch.object(LocalNetworkDetector, "detect", return_value=detection), patch(
        "app.api.v1.endpoints.network.DiscoveryService.execute_discovery",
        side_effect=__import__("asyncio").TimeoutError(),
    ):
        response = await async_client.post(
            "/api/v1/network/devices/discover",
            json={},
            headers=headers,
        )
    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"
