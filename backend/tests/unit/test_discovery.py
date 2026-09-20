"""Unit tests for defensive network discovery subsystem."""

import asyncio
import pytest
from datetime import datetime, timezone
from types import SimpleNamespace
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
from app.services.discovery.arp_scanner import SafeHostDiscoverer
from app.services.discovery.network_provider import LiveNetworkDiscoveryProvider
from app.services.discovery.service import (
    DiscoveryService,
    get_default_discovery_provider,
)


class FakeHostDiscoverer:
    def __init__(self, arp_table, local_ips=None, hostnames=None, mdns=None, netbios=None, llmnr=None, vendors=None, probes=None, neighbors=None):
        self.arp_table = arp_table
        self.local_ips = local_ips or set()
        self.hostnames = hostnames or {}
        self.mdns = mdns or {}
        self.netbios = netbios or {}
        self.llmnr = llmnr or {}
        self.vendors = vendors or {}
        self.probes = probes
        self.neighbors = neighbors or {}

    def read_local_arp_table(self):
        return self.arp_table

    def get_local_ipv4_addresses(self):
        return self.local_ips

    def read_current_windows_neighbors(self):
        return self.neighbors

    async def probe_host(self, ip_address, timeout_seconds=1.0):
        if self.probes is None:
            return (
                bool(SafeHostDiscoverer._normalize_mac(self.arp_table.get(ip_address, "")))
                if self.arp_table
                else None
            )
        return self.probes.get(ip_address, False)

    async def resolve_hostname(self, ip_address):
        return self.hostnames.get(ip_address, "")

    async def resolve_local_hostname(self, ip_address):
        return ""

    async def resolve_mdns_hostname(self, ip_address):
        return self.mdns.get(ip_address, "")

    async def resolve_netbios_hostname(self, ip_address):
        return self.netbios.get(ip_address, "")

    async def resolve_windows_llmnr_hostname(self, ip_address):
        return self.llmnr.get(ip_address, "")

    async def lookup_mac_vendor(self, mac):
        return self.vendors.get(mac, "")


class FakePortProfiler:
    def __init__(self, services_by_ip=None, delay=0.0):
        self.services_by_ip = services_by_ip or {}
        self.delay = delay

    async def scan_host_ports(self, ip_address, ports):
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.services_by_ip.get(ip_address, [])


def make_provider(
    arp_table,
    services_by_ip=None,
    delay=0.0,
    local_ips=None,
    hostnames=None,
    mdns=None,
    netbios=None,
    llmnr=None,
    vendors=None,
    probes=None,
    neighbors=None,
):
    provider = LiveNetworkDiscoveryProvider()
    provider.host_discoverer = FakeHostDiscoverer(
        arp_table,
        local_ips,
        hostnames,
        mdns,
        netbios,
        llmnr,
        vendors,
        probes,
        neighbors,
    )
    provider.port_profiler = FakePortProfiler(services_by_ip, delay)
    return provider


def make_service(port=443):
    return DiscoveredService(
        port=port,
        protocol=Protocol.TCP,
        state=ServiceState.OPEN,
        service_name="https",
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
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
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


@pytest.mark.asyncio
async def test_16_arp_host_without_tcp_service_is_discovered():
    provider = make_provider({
        "192.168.1.50": "AA:BB:CC:DD:EE:50",
    })

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.50"]
    assert result.hosts[0].mac_address == "AA:BB:CC:DD:EE:50"
    assert result.hosts[0].services == []


@pytest.mark.asyncio
async def test_17_arp_host_with_tcp_service_preserves_service():
    provider = make_provider(
        {"192.168.1.50": "AA:BB:CC:DD:EE:50"},
        {"192.168.1.50": [make_service()]},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert len(result.hosts) == 1
    assert result.hosts[0].services[0].port == 443
    assert result.statistics.services_found == 1


@pytest.mark.asyncio
async def test_18_arp_hosts_outside_target_are_ignored():
    provider = make_provider({
        "192.168.1.50": "AA:BB:CC:DD:EE:50",
        "10.0.0.50": "AA:BB:CC:DD:EE:10",
    })

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.50"]


@pytest.mark.asyncio
async def test_19_malformed_arp_entry_is_ignored_safely():
    provider = make_provider({
        "not-an-ip": "AA:BB:CC:DD:EE:50",
        "192.168.1.51": "not-a-mac",
    })

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert result.hosts == []


@pytest.mark.asyncio
async def test_20_duplicate_arp_entries_are_deduplicated():
    output = """
Interface: 192.168.1.1 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.50          aa-bb-cc-dd-ee-50     dynamic
  192.168.1.50          aa-bb-cc-dd-ee-50     dynamic
"""
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "app.services.discovery.arp_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout=output),
    )

    try:
        arp_entries = SafeHostDiscoverer._read_windows_arp_table()
    finally:
        monkeypatch.undo()

    provider = make_provider(arp_entries)

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert len(result.hosts) == 1
    assert result.statistics.hosts_found == 1


@pytest.mark.asyncio
async def test_21_arp_candidate_priority_respects_host_budget():
    provider = make_provider({
        "192.168.1.200": "AA:BB:CC:DD:EE:20",
    })

    result = await provider.discover(
        DiscoveryTarget(
            target_subnet="192.168.1.0/24",
            ports=[443],
            max_hosts=1,
        )
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.200"]


@pytest.mark.asyncio
async def test_22_arp_candidates_avoid_full_subnet_tcp_workload():
    provider = make_provider({
        "192.168.1.200": "AA:BB:CC:DD:EE:20",
    })
    profiler = provider.port_profiler

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert result.statistics.hosts_checked == 254
    assert result.hosts[0].ip_address == "192.168.1.200"
    assert profiler.services_by_ip == {}


@pytest.mark.asyncio
async def test_22b_gateway_only_arp_active_probe_finds_reachable_hosts():
    provider = make_provider(
        {"192.168.1.1": "AA:BB:CC:DD:EE:01"},
        probes={"192.168.1.1": True, "192.168.1.2": True, "192.168.1.3": True},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/29", ports=[443])
    )

    assert {host.ip_address for host in result.hosts} == {
        "192.168.1.1", "192.168.1.2", "192.168.1.3",
    }
    assert result.hosts[1].services == []
    assert any(
        item.method == "active_icmp_probe"
        for item in result.hosts[1].reachability_evidence
    )


@pytest.mark.asyncio
async def test_22c_empty_arp_active_probe_finds_only_reachable_hosts():
    provider = make_provider(
        {},
        probes={"192.168.1.2": True, "192.168.1.3": False},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/29", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.2"]


@pytest.mark.asyncio
async def test_22d_active_probe_respects_local_and_network_boundaries():
    provider = make_provider(
        {},
        local_ips={"192.168.1.2"},
        probes={
            "192.168.1.1": True,
            "192.168.1.2": True,
            "192.168.1.3": True,
        },
    )

    result = await provider.discover(
        DiscoveryTarget(
            target_subnet="192.168.1.0/30",
            ports=[443],
            local_ip="192.168.1.2",
        )
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.1"]


@pytest.mark.asyncio
async def test_22e_active_probe_retains_host_when_identity_resolution_fails():
    provider = make_provider(
        {},
        probes={"192.168.1.2": True},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/30", ports=[443])
    )

    assert result.hosts[0].ip_address == "192.168.1.2"
    assert result.hosts[0].hostname == ""


@pytest.mark.asyncio
async def test_22f_stale_arp_entry_does_not_mark_disconnected_host_online():
    provider = make_provider(
        {"192.168.1.2": "AA:BB:CC:DD:EE:02"},
        probes={"192.168.1.2": False},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/30", ports=[443])
    )

    assert result.hosts == []


@pytest.mark.asyncio
async def test_22g_reconnected_host_is_returned_from_fresh_probe():
    provider = make_provider(
        {"192.168.1.2": "AA:BB:CC:DD:EE:02"},
        probes={"192.168.1.2": True},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/30", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.2"]


@pytest.mark.asyncio
async def test_22h_repeated_scans_use_new_reachability_results():
    provider = make_provider(
        {"192.168.1.2": "AA:BB:CC:DD:EE:02"},
        probes={"192.168.1.2": True},
    )
    target = DiscoveryTarget(target_subnet="192.168.1.0/30", ports=[443])

    first = await provider.discover(target)
    provider.host_discoverer.probes["192.168.1.2"] = False
    second = await provider.discover(target)
    provider.host_discoverer.probes["192.168.1.2"] = True
    third = await provider.discover(target)

    assert [host.ip_address for host in first.hosts] == ["192.168.1.2"]
    assert second.hosts == []
    assert [host.ip_address for host in third.hosts] == ["192.168.1.2"]


@pytest.mark.asyncio
async def test_22i_active_windows_neighbor_can_prove_current_attachment():
    provider = make_provider(
        {"192.168.1.2": "AA:BB:CC:DD:EE:02"},
        probes={"192.168.1.2": False},
        neighbors={"192.168.1.2": "AA:BB:CC:DD:EE:02"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/30", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.2"]
    assert any(
        item.method == "windows_neighbor_reachable"
        for item in result.hosts[0].reachability_evidence
    )


@pytest.mark.asyncio
async def test_23_no_arp_candidates_keep_full_subnet_fallback():
    provider = make_provider({})

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert result.statistics.hosts_checked == 254


@pytest.mark.asyncio
async def test_24_overall_discovery_timeout_is_enforced():
    provider = make_provider(
        {"192.168.1.50": "AA:BB:CC:DD:EE:50"},
        delay=2.0,
    )
    target = DiscoveryTarget(
        target_subnet="192.168.1.50",
        ports=[443],
        timeout_seconds=1.0,
    )

    result = await provider.discover(target)

    assert result.hosts == []
    assert any("timeout" in error.lower() for error in result.errors)


@pytest.mark.asyncio
async def test_25_arp_network_and_broadcast_addresses_are_excluded():
    provider = make_provider({
        "192.168.1.0": "AA:BB:CC:DD:EE:00",
        "192.168.1.255": "AA:BB:CC:DD:EE:FF",
        "192.168.1.50": "AA:BB:CC:DD:EE:50",
    })

    result = await provider.discover(
        DiscoveryTarget(target_subnet="192.168.1.0/24", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["192.168.1.50"]


@pytest.mark.asyncio
async def test_26_local_ip_is_excluded_but_remote_arp_host_remains():
    provider = make_provider(
        {
            "10.57.15.139": "AA:BB:CC:DD:EE:39",
            "10.57.15.102": "62:B8:A9:33:44:2C",
        },
        local_ips={"10.57.15.139"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["10.57.15.102"]
    assert result.hosts[0].mac_address == "62:B8:A9:33:44:2C"


@pytest.mark.asyncio
async def test_27_out_of_scope_arp_host_remains_excluded():
    provider = make_provider({
        "10.57.15.102": "62:B8:A9:33:44:2C",
        "10.57.16.102": "AA:BB:CC:DD:EE:16",
    })

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert [host.ip_address for host in result.hosts] == ["10.57.15.102"]


@pytest.mark.asyncio
async def test_28_hostname_is_preserved_when_local_resolution_succeeds():
    provider = make_provider(
        {"10.57.15.41": "AA:E1:15:74:86:E4"},
        hostnames={"10.57.15.41": "gateway.local"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].hostname == "gateway.local"
    assert result.hosts[0].hostname_evidence[0].method == "reverse_dns"


@pytest.mark.asyncio
async def test_29_hostname_remains_unknown_when_resolution_fails():
    provider = make_provider({"10.57.15.102": "2E:C5:4F:A9:7D:1A"})

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].hostname == ""


@pytest.mark.asyncio
async def test_29b_mdns_hostname_is_used_after_dns_fails():
    provider = make_provider(
        {"10.57.15.130": "2E:C5:4F:A9:7D:1A"},
        mdns={"10.57.15.130": "phone.local"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].hostname == "phone.local"
    assert any(item.method == "mdns_or_dns_sd" for item in result.hosts[0].hostname_evidence)


@pytest.mark.asyncio
async def test_29c_netbios_hostname_is_used_after_other_local_resolution_fails():
    provider = make_provider(
        {"10.57.15.130": "2E:C5:4F:A9:7D:1A"},
        netbios={"10.57.15.130": "PHONE"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].hostname == "PHONE"
    assert any(item.method == "windows_nbtstat" for item in result.hosts[0].hostname_evidence)


@pytest.mark.asyncio
async def test_29d_windows_llmnr_hostname_is_used_after_other_resolution_fails():
    provider = make_provider(
        {"10.57.15.41": "AA:E1:15:74:86:E4"},
        llmnr={"10.57.15.41": "android-hotspot.local"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].hostname == "android-hotspot.local"
    assert any(item.method == "windows_llmnr" for item in result.hosts[0].hostname_evidence)


@pytest.mark.asyncio
async def test_30_randomized_mac_is_not_assigned_a_manufacturer():
    provider = make_provider({"10.57.15.102": "2E:C5:4F:A9:7D:1A"})

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].vendor == ""
    assert result.hosts[0].vendor_evidence[0].method == "mac_local_administered_bit"


@pytest.mark.asyncio
async def test_30b_globally_administered_mac_uses_real_vendor_collaborator():
    provider = make_provider(
        {"10.57.15.41": "00:E1:15:74:86:E4"},
        vendors={"00:E1:15:74:86:E4": "Example Networks"},
    )

    result = await provider.discover(
        DiscoveryTarget(target_subnet="10.57.15.0/24", ports=[443])
    )

    assert result.hosts[0].vendor == "Example Networks"
    assert result.hosts[0].vendor_evidence[0].method == "ieee_oui_lookup"


def test_31_globally_administered_mac_has_no_unsupported_vendor_claim():
    assert SafeHostDiscoverer.mac_vendor_label("00:E1:15:74:86:E4") == ""
