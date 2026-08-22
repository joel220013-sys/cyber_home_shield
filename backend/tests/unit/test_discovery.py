"""Unit tests for defensive network discovery subsystem."""

import asyncio
import pytest
from datetime import datetime
from app.core.exceptions import ScopeValidationError
from app.core.security import validate_defensive_target_scope
from app.models.enums import DeviceType, Protocol
from app.schemas.device import DeviceCreate
from app.services.discovery.base import BaseDiscoveryProvider
from app.services.discovery.models import (
    DiscoveredHost,
    DiscoveredService,
    DiscoveryEvidence,
    DiscoveryResult,
    DiscoveryStatistics,
    DiscoveryTarget,
    DryRunResult,
    ServiceState,
)
from app.services.discovery.port_profiler import SafePortProfiler, WELL_KNOWN_SERVICES
from app.services.discovery.network_provider import LiveNetworkDiscoveryProvider
from app.services.discovery.service import (
    DiscoveryService,
    get_default_discovery_provider,
)


@pytest.mark.asyncio
async def test_1_private_target_accepted():
    """Verify that valid RFC 1918 private IPv4 subnets and IPs are accepted."""
    valid_targets = [
        "192.168.1.0/24",
        "192.168.0.1",
        "10.0.0.0/8",
        "10.10.5.1",
        "172.16.0.0/12",
        "172.20.1.100",
    ]
    for target in valid_targets:
        assert validate_defensive_target_scope(target) is not None


@pytest.mark.asyncio
async def test_2_public_target_rejected():
    """Verify that public Internet addresses are rejected with ScopeValidationError."""
    public_targets = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "208.67.222.222"]
    for target in public_targets:
        with pytest.raises(ScopeValidationError):
            validate_defensive_target_scope(target)


@pytest.mark.asyncio
async def test_3_loopback_rejected():
    """Verify that loopback addresses are rejected."""
    loopbacks = ["127.0.0.1", "127.0.0.0/8", "127.0.1.1"]
    for target in loopbacks:
        with pytest.raises(ScopeValidationError):
            validate_defensive_target_scope(target)


@pytest.mark.asyncio
async def test_4_multicast_rejected():
    """Verify that multicast addresses are rejected."""
    multicasts = ["224.0.0.1", "239.255.255.250"]
    for target in multicasts:
        with pytest.raises(ScopeValidationError):
            validate_defensive_target_scope(target)


@pytest.mark.asyncio
async def test_5_invalid_cidr_rejected():
    """Verify that malformed IP and CIDR strings are rejected."""
    invalid_targets = ["192.168.1.0/99", "not-an-ip", "999.999.999.999", "192.168.1.1/33"]
    for target in invalid_targets:
        with pytest.raises((ScopeValidationError, ValueError)):
            validate_defensive_target_scope(target)


@pytest.mark.asyncio
async def test_6_discovery_target_validation():
    """Verify DiscoveryTarget Pydantic validation for private scope, ports, and bounds."""
    target = DiscoveryTarget(
        target_subnet="192.168.1.0/24",
        ports=[80, 443, 22],
        max_hosts=50,
        timeout_seconds=15.0,
    )
    assert target.target_subnet == "192.168.1.0/24"
    assert target.ports == [22, 80, 443]  # sorted & unique
    assert target.max_hosts == 50

    # Test invalid target inside DiscoveryTarget model
    with pytest.raises(ValueError):
        DiscoveryTarget(target_subnet="8.8.8.8")


@pytest.mark.asyncio
async def test_7_dry_run_performs_zero_network_operations():
    """Verify that dry-run mode calculates scope and explicitly performs 0 network operations."""
    service = DiscoveryService(provider=LiveNetworkDiscoveryProvider())
    empty_result, dry_run = await service.execute_discovery(
        target_str="192.168.1.0/24",
        dry_run=True,
    )
    assert dry_run is not None
    assert dry_run.network_operations_performed == 0
    assert dry_run.total_hosts_in_scope >= 254
    assert len(dry_run.candidate_hosts) > 0
    assert "0 packets or sockets sent" in dry_run.execution_plan


@pytest.mark.asyncio
async def test_8_default_provider_is_live_network_provider():
    """Verify configured discovery resolves to the real network provider."""
    assert isinstance(
        get_default_discovery_provider(),
        LiveNetworkDiscoveryProvider,
    )


@pytest.mark.asyncio
async def test_9_live_provider_dry_run_does_not_fabricate_hosts():
    """Verify the live provider's dry-run only describes scope, not devices."""
    provider = LiveNetworkDiscoveryProvider()
    target = DiscoveryTarget(target_subnet="192.168.1.0/24")
    result = await provider.dry_run(target)

    assert result.network_operations_performed == 0
    assert result.candidate_hosts


@pytest.mark.asyncio
async def test_10_invalid_provider_fails_clearly(monkeypatch):
    """Verify invalid provider configuration fails without a fallback."""
    monkeypatch.setattr(
        "app.services.discovery.service.settings.DISCOVERY_PROVIDER",
        "unsupported-provider",
    )

    with pytest.raises(ValueError, match="only 'network' is supported"):
        get_default_discovery_provider()


@pytest.mark.asyncio
async def test_11_port_validation():
    """Verify port bounds (1-65535) and rejection of invalid ports."""
    with pytest.raises(ValueError):
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[0])

    with pytest.raises(ValueError):
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[70000])

    with pytest.raises(ValueError):
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[])


@pytest.mark.asyncio
async def test_12_timeout_handling():
    """Verify SafePortProfiler handles connect timeouts gracefully without raising uncaught exceptions."""
    # Target a non-routable private IP with extremely short timeout
    profiler = SafePortProfiler(connect_timeout=0.01, max_concurrent=5)
    res = await profiler.check_single_port("10.255.255.1", 80)
    assert res.state in [ServiceState.TIMEOUT, ServiceState.FILTERED, ServiceState.CLOSED]
    assert res.port == 80


@pytest.mark.asyncio
async def test_13_bounded_concurrency():
    """Verify bounded concurrency semaphore is respected."""
    profiler = SafePortProfiler(connect_timeout=0.05, max_concurrent=2)
    assert profiler._semaphore._value == 2


@pytest.mark.asyncio
async def test_14_discovery_result_validation():
    """Verify DiscoveryResult model fields and statistics."""
    stats = DiscoveryStatistics(
        hosts_checked=10,
        hosts_found=4,
        services_checked=90,
        services_found=8,
        duration_seconds=1.25,
    )
    result = DiscoveryResult(
        target="192.168.1.0/24",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        hosts=[],
        services=[],
        evidence=[],
        errors=[],
        statistics=stats,
    )
    assert result.statistics.hosts_found == 4
    assert result.statistics.duration_seconds == 1.25


@pytest.mark.asyncio
async def test_15_device_normalization():
    """Verify normalization preserves raw facts and does NOT fabricate OS, vendor, or device model."""
    host = DiscoveredHost(
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="printer.local",
        is_online=True,
    )
    normalized: DeviceCreate = DiscoveryService.normalize_host_to_device(host)

    assert normalized.ip_address == "192.168.1.50"
    assert normalized.mac_address == "AA:BB:CC:DD:EE:FF"
    assert normalized.hostname == "printer.local"
    # STRICT DEFENSIVE RULE: Unknown attributes remain unknown / un-fabricated
    assert normalized.vendor == "Unknown Vendor"
    assert normalized.device_type == DeviceType.UNKNOWN
    assert normalized.is_trusted is False

