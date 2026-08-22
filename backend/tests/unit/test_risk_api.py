"""Unit and integration tests for Risk API endpoints."""

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.models.device import Device
from app.models.enums import DeviceType, FindingStatus, Protocol, Severity
from app.models.open_port import OpenPort
from app.models.security_finding import SecurityFinding
from app.models.network_event import NetworkEvent
from app.api.v1.endpoints.risk import _generate_and_persist_findings


@pytest.mark.asyncio
async def test_26_get_network_posture_endpoint(async_client: AsyncClient, db_session):
    """Verify GET /api/v1/risk/posture returns 200 with complete network posture statistics."""
    # Seed a device with an open port in the test database
    dev = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.10",
        mac_address="AA:BB:CC:11:22:33",
        hostname="router.home.arpa",
        device_type=DeviceType.ROUTER,
    )
    db_session.add(dev)
    await db_session.flush()

    port = OpenPort(
        device_id=dev.id,
        port_number=80,
        protocol=Protocol.TCP,
        service_name="http",
    )
    db_session.add(port)
    await db_session.commit()

    response = await async_client.get("/api/v1/risk/posture")
    assert response.status_code == 200
    data = response.json()
    assert "network_risk_score" in data
    assert data["total_devices"] >= 1
    assert "device_scores" in data
    assert str(dev.id) in data["device_scores"]


@pytest.mark.asyncio
async def test_27_get_device_risk_endpoint(async_client: AsyncClient, db_session):
    """Verify GET /api/v1/risk/devices/{id} computes and returns device risk assessment."""
    dev = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.50",
        mac_address="11:22:33:44:55:66",
        hostname="nas.home.arpa",
        device_type=DeviceType.STORAGE,
    )
    db_session.add(dev)
    await db_session.flush()

    port = OpenPort(
        device_id=dev.id,
        port_number=445,
        protocol=Protocol.TCP,
        service_name="smb",
    )
    db_session.add(port)
    await db_session.commit()

    response = await async_client.get(f"/api/v1/risk/devices/{dev.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["device_id"] == str(dev.id)
    assert data["exposure_subscore"] == 35.0
    assert data["open_risky_ports_count"] == 1
    assert len(data["findings"]) >= 1
    assert "score_breakdown" in data


@pytest.mark.asyncio
async def test_28_get_device_risk_missing_device(async_client: AsyncClient):
    """Verify GET /api/v1/risk/devices/{id} returns 404 when device does not exist."""
    random_id = uuid.uuid4()
    response = await async_client.get(f"/api/v1/risk/devices/{random_id}")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_29_get_device_risk_invalid_id(async_client: AsyncClient):
    """Verify GET /api/v1/risk/devices/{id} returns 400 for malformed UUID string."""
    response = await async_client.get("/api/v1/risk/devices/not-a-valid-uuid")
    assert response.status_code == 400
    assert "invalid uuid format" in response.json()["detail"].lower()


async def _device_with_port(db_session, port_number: int) -> Device:
    device = Device(
        id=uuid.uuid4(),
        ip_address=f"192.168.1.{10 + port_number % 200}",
        mac_address=f"AA:BB:CC:{port_number:06X}",
        hostname=f"device-{port_number}",
        device_type=DeviceType.IOT,
    )
    device.ports.append(
        OpenPort(
            id=uuid.uuid4(),
            port_number=port_number,
            protocol=Protocol.TCP,
            service_name="test",
        )
    )
    db_session.add(device)
    await db_session.commit()
    result = await db_session.execute(
        select(Device)
        .where(Device.id == device.id)
        .options(
            selectinload(Device.ports),
            selectinload(Device.findings),
            selectinload(Device.events),
        )
    )
    return result.scalar_one()


@pytest.mark.asyncio
async def test_stale_port_finding_is_resolved(db_session):
    """A finding disappears when its previously open port is absent."""
    device = await _device_with_port(db_session, 445)

    active = await _generate_and_persist_findings(db_session, device)
    assert len(active) == 1

    device.ports.clear()
    active = await _generate_and_persist_findings(db_session, device)

    assert active == []
    finding = (
        await db_session.execute(
            select(SecurityFinding).where(
                SecurityFinding.device_id == device.id
            )
        )
    ).scalar_one()
    assert finding.status == FindingStatus.RESOLVED


@pytest.mark.asyncio
async def test_repeated_port_finding_does_not_duplicate(db_session):
    """Repeated observations keep one active finding."""
    device = await _device_with_port(db_session, 445)

    await _generate_and_persist_findings(db_session, device)
    await _generate_and_persist_findings(db_session, device)

    findings = (
        await db_session.execute(
            select(SecurityFinding).where(
                SecurityFinding.device_id == device.id,
                SecurityFinding.status == FindingStatus.OPEN,
            )
        )
    ).scalars().all()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_port_findings_are_isolated_per_device(db_session):
    """The same port on two devices produces independent findings."""
    first = await _device_with_port(db_session, 445)
    second = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.250",
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="second-device",
        device_type=DeviceType.IOT,
    )
    second.ports.append(
        OpenPort(
            id=uuid.uuid4(),
            port_number=445,
            protocol=Protocol.TCP,
            service_name="test",
        )
    )
    db_session.add(second)
    await db_session.commit()

    second = (
        await db_session.execute(
            select(Device)
            .where(Device.id == second.id)
            .options(
                selectinload(Device.ports),
                selectinload(Device.findings),
                selectinload(Device.events),
            )
        )
    ).scalar_one()

    await _generate_and_persist_findings(db_session, first)
    await _generate_and_persist_findings(db_session, second)

    findings = (
        await db_session.execute(select(SecurityFinding))
    ).scalars().all()
    assert {finding.device_id for finding in findings} == {
        first.id,
        second.id,
    }


@pytest.mark.asyncio
async def test_anomaly_finding_is_not_resolved_by_port_reconciliation(db_session):
    """Anomaly findings remain active when no current port finding exists."""
    device = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.240",
        mac_address="AA:BB:CC:11:22:33",
        hostname="anomaly-device",
        device_type=DeviceType.IOT,
    )
    device.findings.append(
        SecurityFinding(
            id=uuid.uuid4(),
            device_id=device.id,
            title="Network Telemetry Anomaly Detected",
            category="ANOMALY",
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            description="Anomaly test finding.",
            remediation_steps="Review telemetry.",
            cve_id="",
            evidence={"source": "anomaly_detector"},
        )
    )
    db_session.add(device)
    await db_session.commit()

    device = (
        await db_session.execute(
            select(Device)
            .where(Device.id == device.id)
            .options(
                selectinload(Device.ports),
                selectinload(Device.findings),
                selectinload(Device.events),
            )
        )
    ).scalar_one()

    active = await _generate_and_persist_findings(db_session, device)

    assert len(active) == 1
    assert active[0].category == "ANOMALY"


@pytest.mark.asyncio
async def test_multiple_stale_port_findings_are_resolved(db_session):
    """All disappeared current port findings are resolved together."""
    device = Device(
        id=uuid.uuid4(),
        ip_address="192.168.1.230",
        mac_address="AA:BB:CC:44:55:66",
        hostname="multi-port-device",
        device_type=DeviceType.IOT,
    )
    for port_number in (80, 445):
        device.ports.append(
            OpenPort(
                id=uuid.uuid4(),
                port_number=port_number,
                protocol=Protocol.TCP,
                service_name="test",
            )
        )
    db_session.add(device)
    await db_session.commit()

    device = (
        await db_session.execute(
            select(Device)
            .where(Device.id == device.id)
            .options(
                selectinload(Device.ports),
                selectinload(Device.findings),
                selectinload(Device.events),
            )
        )
    ).scalar_one()

    assert len(await _generate_and_persist_findings(db_session, device)) == 2
    device.ports.clear()

    assert await _generate_and_persist_findings(db_session, device) == []
    resolved = (
        await db_session.execute(
            select(SecurityFinding).where(
                SecurityFinding.device_id == device.id
            )
        )
    ).scalars().all()
    assert len(resolved) == 2
    assert all(finding.status == FindingStatus.RESOLVED for finding in resolved)

