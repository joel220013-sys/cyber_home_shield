"""Live defensive network discovery provider using safe TCP connect probes and local ARP."""

import asyncio
import ipaddress
from datetime import datetime, timezone
from typing import List, Optional

from app.config import settings
from app.core.logging import logger
from app.services.discovery.arp_scanner import SafeHostDiscoverer
from app.services.discovery.base import BaseDiscoveryProvider
from app.services.discovery.models import (
    DiscoveredHost,
    DiscoveredService,
    DiscoveryEvidence,
    DiscoveryResult,
    DiscoveryStatistics,
    DiscoveryTarget,
    DryRunResult,
)
from app.services.discovery.port_profiler import SafePortProfiler


class LiveNetworkDiscoveryProvider(BaseDiscoveryProvider):
    """
    Production defensive scanner using non-intrusive TCP connect
    and local ARP/neighbour-table information.
    """

    def __init__(self) -> None:
        self.port_profiler = SafePortProfiler(
            connect_timeout=settings.CONNECT_TIMEOUT,
            max_concurrent=settings.MAX_CONCURRENT_CHECKS,
        )
        self.host_discoverer = SafeHostDiscoverer()

    async def _audit_host(
        self,
        ip_str: str,
        ports: List[int],
        arp_table: dict,
        reachability_method: str = "",
        deadline: Optional[float] = None,
    ) -> Optional[DiscoveredHost]:
        """Audit a single host for reachability and configured open ports."""

        now = datetime.now(timezone.utc)
        mac = arp_table.get(ip_str, "")

        remaining = (
            max(deadline - asyncio.get_running_loop().time(), 0.0)
            if deadline is not None
            else settings.CONNECT_TIMEOUT
        )
        if remaining <= 0:
            return None

        try:
            port_timeout = min(remaining, 3.0) if remaining > 0 else 0.5
            open_services = await asyncio.wait_for(
                self.port_profiler.scan_host_ports(ip_str, ports),
                timeout=port_timeout,
            )
        except (asyncio.TimeoutError, Exception):
            open_services = []

        # ARP is only a candidate source. Current reachability must come from
        # this scan's ICMP probe or a successful TCP connection.
        if open_services or reachability_method:
            try:
                hostname_timeout = min(
                    max(deadline - asyncio.get_running_loop().time(), 0.0)
                    if deadline is not None
                    else settings.CONNECT_TIMEOUT,
                    0.5,
                )
                hostname, hostname_evidence = await asyncio.wait_for(
                    self._resolve_hostname(ip_str),
                    timeout=hostname_timeout,
                )
            except asyncio.TimeoutError:
                hostname = ""
                hostname_evidence = []
            vendor = SafeHostDiscoverer.mac_vendor_label(mac)
            vendor_evidence: list[DiscoveryEvidence] = []
            if vendor:
                vendor_evidence.append(DiscoveryEvidence(
                    method="mac_local_administered_bit",
                    timestamp=now,
                    raw_response="MAC has the locally administered bit set; no OUI vendor was assigned.",
                ))
                # A privacy label is evidence, not a manufacturer identity.
                vendor = ""
            else:
                vendor_timeout = min(
                    max(deadline - asyncio.get_running_loop().time(), 0.0)
                    if deadline is not None
                    else settings.CONNECT_TIMEOUT,
                    0.5,
                )
                try:
                    vendor = await asyncio.wait_for(
                        self.host_discoverer.lookup_mac_vendor(mac),
                        timeout=vendor_timeout,
                    )
                except asyncio.TimeoutError:
                    vendor = ""
                if vendor:
                    vendor_evidence.append(DiscoveryEvidence(
                        method="ieee_oui_lookup",
                        timestamp=now,
                        raw_response=f"IEEE OUI registry matched {vendor}.",
                    ))
                elif mac:
                    vendor_evidence.append(DiscoveryEvidence(
                        method="ieee_oui_lookup",
                        timestamp=now,
                        raw_response="IEEE OUI lookup returned no manufacturer for the observed MAC.",
                    ))
            reachability_evidence = []
            if mac:
                reachability_evidence.append(DiscoveryEvidence(
                    method="local_arp_neighbor_table",
                    timestamp=now,
                    raw_response="IP/MAC mapping observed in the local neighbor table.",
                ))
            if open_services:
                reachability_evidence.append(DiscoveryEvidence(
                    method="bounded_tcp_connect",
                    timestamp=now,
                    raw_response="At least one configured TCP service accepted a connection.",
                ))
            if reachability_method and reachability_method != "local_arp_neighbor_table":
                reachability_evidence.append(DiscoveryEvidence(
                    method=reachability_method,
                    timestamp=now,
                    raw_response="Bounded local reachability probe received a response.",
                ))

            return DiscoveredHost(
                ip_address=ip_str,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                hostname_evidence=hostname_evidence,
                vendor_evidence=vendor_evidence,
                reachability_evidence=reachability_evidence,
                is_online=True,
                services=open_services,
                first_seen=now,
                last_seen=now,
                discovery_method=reachability_method or "defensive_tcp_arp",
            )

        return None

    async def _resolve_hostname(self, ip_address: str) -> tuple[str, list[DiscoveryEvidence]]:
        """Try local identity sources in order without fabricating names."""

        checked: list[DiscoveryEvidence] = []
        for resolver_name, method in (
            ("resolve_hostname", "reverse_dns"),
            ("resolve_local_hostname", "windows_name_service"),
            ("resolve_mdns_hostname", "mdns_or_dns_sd"),
            ("resolve_netbios_hostname", "windows_nbtstat"),
            ("resolve_windows_llmnr_hostname", "windows_llmnr"),
            ("resolve_windows_ping_hostname", "windows_ping_a"),
        ):
            resolver = getattr(self.host_discoverer, resolver_name, None)
            if resolver is None:
                continue
            try:
                hostname = await asyncio.wait_for(resolver(ip_address), timeout=0.2)
            except Exception:
                checked.append(DiscoveryEvidence(
                    method=method,
                    raw_response=f"{method} could not resolve a hostname for {ip_address}.",
                ))
                continue
            if hostname:
                return hostname, checked + [DiscoveryEvidence(
                    method=method,
                    raw_response=f"Resolved hostname {hostname} for {ip_address}.",
                )]
            checked.append(DiscoveryEvidence(
                method=method,
                raw_response=f"{method} returned no hostname for {ip_address}.",
            ))

        return "", checked

    async def discover(
        self,
        target: DiscoveryTarget,
    ) -> DiscoveryResult:
        """Execute defensive network discovery against an authorized target."""

        start_time = datetime.now(timezone.utc)

        errors: List[str] = []
        discovered_hosts: List[DiscoveredHost] = []
        all_services: List[DiscoveredService] = []

        # ------------------------------------------------------------------
        # Read local ARP/neighbour table
        # ------------------------------------------------------------------

        arp_table = {
            ip_str: normalized_mac
            for ip_str, mac in self.host_discoverer.read_local_arp_table().items()
            if (
                (normalized_mac := SafeHostDiscoverer._normalize_mac(mac))
            )
        }
        read_neighbors = getattr(
            self.host_discoverer,
            "read_current_windows_neighbors",
            None,
        )
        current_neighbors = read_neighbors() if read_neighbors else {}
        for ip_str, mac in current_neighbors.items():
            normalized_mac = SafeHostDiscoverer._normalize_mac(mac)
            if normalized_mac:
                arp_table.setdefault(ip_str, normalized_mac)
        local_ips = self.host_discoverer.get_local_ipv4_addresses()
        if target.local_ip:
            local_ips.add(target.local_ip.strip())

        logger.debug(
            "Read %d private hosts from local ARP table.",
            len(arp_table),
        )

        # --------------------------------------------------------------
        # Active Layer-2 ARP scan (catches hosts that ignore ICMP, e.g.
        # under client isolation or host firewalls). Safely no-ops to
        # {} if scapy/Npcap/privileges are unavailable.
        # --------------------------------------------------------------

        active_arp_hosts: dict[str, str] = {}
        active_arp_fn = getattr(self.host_discoverer, "active_arp_scan", None)
        if settings.ENABLE_ACTIVE_ARP_SCAN and "/" in target.target_subnet and active_arp_fn:
            active_arp_hosts = await active_arp_fn(
                target.target_subnet.strip(),
                timeout_seconds=settings.ACTIVE_ARP_SCAN_TIMEOUT,
            )
            for ip_str, mac in active_arp_hosts.items():
                arp_table[ip_str] = mac
            logger.debug(
                "Active ARP scan found %d additional hosts.",
                len(active_arp_hosts),
            )

        # ------------------------------------------------------------------
        # Build candidate IP list
        # ------------------------------------------------------------------

        target_str = target.target_subnet.strip()

        try:
            if "/" in target_str:
                network = ipaddress.ip_network(
                    target_str,
                    strict=False,
                )

                subnet_hosts = [
                    str(ip)
                    for ip in network.hosts()
                ]
            else:
                network = ipaddress.ip_network(
                    f"{target_str}/32",
                    strict=False,
                )
                subnet_hosts = [target_str]

            # ARP is passive evidence and is prioritized, but it must not
            # suppress active probing of the other authorized local hosts.
            scoped_arp_hosts = [
                ip_str
                for ip_str in arp_table
                if self._is_valid_target_ip(ip_str, network, local_ips)
            ]
            scoped_current_neighbors = [
                ip_str
                for ip_str in current_neighbors
                if self._is_valid_target_ip(ip_str, network, local_ips)
            ]
            scoped_active_arp_hosts = [
                ip_str
                for ip_str in active_arp_hosts
                if self._is_valid_target_ip(ip_str, network, local_ips)
            ]
            scoped_subnet_hosts = [
                ip_str
                for ip_str in subnet_hosts
                if self._is_valid_target_ip(ip_str, network, local_ips)
            ]
            candidate_ips = list(dict.fromkeys(
                scoped_current_neighbors
                + scoped_active_arp_hosts
                + scoped_arp_hosts
                + [ip_str for ip_str in scoped_subnet_hosts if ip_str not in scoped_arp_hosts]
            ))[: target.max_hosts]

        except ValueError as exc:
            errors.append(
                f"Invalid discovery target {target_str!r}: {exc}"
            )

            end_time = datetime.now(timezone.utc)

            return DiscoveryResult(
                target=target.target_subnet,
                started_at=start_time,
                completed_at=end_time,
                hosts=[],
                services=[],
                evidence=[],
                errors=errors,
                statistics=DiscoveryStatistics(
                    hosts_checked=0,
                    hosts_found=0,
                    services_checked=0,
                    services_found=0,
                    duration_seconds=round(
                        (end_time - start_time).total_seconds(),
                        3,
                    ),
                ),
            )

        # ------------------------------------------------------------------
        # Bounded host concurrency
        # ------------------------------------------------------------------

        semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_CHECKS)
        deadline = asyncio.get_running_loop().time() + target.timeout_seconds

        probe_results: dict[str, Optional[bool]] = {}
        probe_candidates = [
            ip
            for ip in candidate_ips
            if ip not in scoped_current_neighbors
            and ip not in scoped_active_arp_hosts
        ]

        async def bounded_probe(ip: str) -> tuple[str, Optional[bool]]:
            async with semaphore:
                try:
                    probe = getattr(self.host_discoverer, "probe_host", None)
                    if probe is None:
                        return ip, None
                    return ip, await probe(
                        ip,
                        timeout_seconds=settings.ICMP_PROBE_TIMEOUT,
                    )
                except Exception as exc:
                    logger.debug("Error probing host %s: %s", ip, exc)
                    return ip, None

        if probe_candidates:
            probe_tasks = [asyncio.create_task(bounded_probe(ip)) for ip in probe_candidates]
            try:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                probe_pairs = await asyncio.wait_for(
                    asyncio.gather(*probe_tasks),
                    timeout=remaining,
                )
                probe_results = dict(probe_pairs)
            except asyncio.TimeoutError:
                for task in probe_tasks:
                    if not task.done():
                        task.cancel()
                gathered_probes = await asyncio.gather(*probe_tasks, return_exceptions=True)
                probe_results = {
                    res[0]: res[1]
                    for res in gathered_probes
                    if isinstance(res, tuple) and len(res) == 2
                }
                for ip in probe_candidates:
                    probe_results.setdefault(ip, False)
                errors.append(
                    f"Discovery exceeded the {target.timeout_seconds:.1f}-second timeout."
                )

        # A successful active probe can populate the ARP cache. Refresh once
        # after probing so the returned identity can include that MAC.
        if any(value is True for value in probe_results.values()):
            refreshed_arp = self.host_discoverer.read_local_arp_table()
            for ip_str, mac in refreshed_arp.items():
                if self._is_valid_target_ip(ip_str, network, local_ips):
                    normalized_mac = SafeHostDiscoverer._normalize_mac(mac)
                    if normalized_mac:
                        arp_table[ip_str] = normalized_mac

        # Every candidate must have fresh evidence to be marked *online*.
        # A failed ICMP probe is never converted into reachability by
        # stale ARP alone -- but a stale/passive ARP entry still earns a
        # bounded TCP audit, because an open service is its own proof of
        # liveness independent of ICMP. Without this, any host that only
        # showed up via a passive ARP-table read (e.g. `arp -a`) and
        # failed a single 0.5-1.2s ping (common on a phone hotspot with
        # AP isolation, or a host that simply doesn't answer ICMP) was
        # dropped before ever being TCP-scanned, so it could never
        # appear in results even if genuinely reachable.
        audit_candidates = [
            (
                ip,
                "windows_neighbor_reachable"
                if ip in scoped_current_neighbors
                else "active_arp_reply"
                if ip in scoped_active_arp_hosts
                else "active_icmp_probe"
                if probe_results.get(ip) is True
                else "",
            )
            for ip in candidate_ips
            if (
                ip in scoped_current_neighbors
                or ip in scoped_active_arp_hosts
                or ip in scoped_arp_hosts
                or probe_results.get(ip) is True
                or probe_results.get(ip) is None
            )
        ]

        async def bounded_audit(
            item: tuple[str, str],
        ) -> Optional[DiscoveredHost]:
            ip, reachability_method = item
            async with semaphore:
                try:
                    return await self._audit_host(
                        ip,
                        target.ports,
                        arp_table,
                        reachability_method,
                        deadline,
                    )

                except Exception as exc:
                    logger.debug(
                        "Error auditing host %s: %s",
                        ip,
                        exc,
                    )
                    return None

        tasks = [
            asyncio.create_task(bounded_audit(item))
            for item in audit_candidates
        ]

        try:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=False),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            for task in tasks:
                if not task.done():
                    task.cancel()

            gathered = await asyncio.gather(
                *tasks,
                return_exceptions=True,
            )
            errors.append(
                f"Discovery exceeded the {target.timeout_seconds:.1f}-second timeout."
            )
            results = [
                res
                for res in gathered
                if isinstance(res, DiscoveredHost)
            ]

        # ------------------------------------------------------------------
        # Collect discovered hosts and services
        # ------------------------------------------------------------------

        for host in results:
            if host is not None:
                discovered_hosts.append(host)
                all_services.extend(host.services)

        # ------------------------------------------------------------------
        # Build result
        # ------------------------------------------------------------------

        end_time = datetime.now(timezone.utc)

        duration = (
            end_time - start_time
        ).total_seconds()

        return DiscoveryResult(
            target=target.target_subnet,
            started_at=start_time,
            completed_at=end_time,
            hosts=discovered_hosts,
            services=all_services,
            evidence=[
                DiscoveryEvidence(
                    method="defensive_network_discovery",
                    timestamp=end_time,
                    raw_response=(
                        f"Prioritized {len(scoped_arp_hosts)} passive ARP "
                        f"candidates and recognized {len(scoped_current_neighbors)} "
                        "active Windows neighbor observations; active ARP scan "
                        f"replied from {len(scoped_active_arp_hosts)} hosts; "
                        f"actively probed {len(probe_candidates)} additional "
                        f"authorized candidates; audited {len(audit_candidates)} "
                        f"on {target.target_subnet}."
                    ),
                    response_time_ms=round(
                        duration * 1000,
                        2,
                    ),
                )
            ],
            errors=errors,
            statistics=DiscoveryStatistics(
                hosts_checked=len(candidate_ips),
                hosts_found=len(discovered_hosts),
                services_checked=(
                    len(audit_candidates)
                    * len(target.ports)
                ),
                services_found=len(all_services),
                duration_seconds=round(
                    duration,
                    3,
                ),
            ),
        )

    @staticmethod
    def _is_valid_target_ip(
        ip_str: str,
        network: ipaddress.IPv4Network,
        local_ips: set[str] | None = None,
    ) -> bool:
        """Return whether an ARP key is a valid host inside the target."""

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        return (
            isinstance(ip, ipaddress.IPv4Address)
            and ip in network
            and (
                network.prefixlen == 32
                or (
                    ip != network.network_address
                    and ip != network.broadcast_address
                )
            )
            and ip.is_private
            and not ip.is_loopback
            and not ip.is_multicast
            and str(ip) not in (local_ips or set())
        )

    async def dry_run(
        self,
        target: DiscoveryTarget,
    ) -> DryRunResult:
        """
        Perform zero-network calculation of target subnet scope.

        No sockets, TCP connections, ARP requests, or network packets
        are generated by this method.
        """

        target_str = target.target_subnet.strip()

        try:
            if "/" in target_str:
                network = ipaddress.ip_network(
                    target_str,
                    strict=False,
                )

                hosts = [
                    str(ip)
                    for ip in list(network.hosts())[: target.max_hosts]
                ]

                if network.prefixlen < 31:
                    total_hosts = max(
                        network.num_addresses - 2,
                        1,
                    )
                else:
                    total_hosts = network.num_addresses

            else:
                hosts = [target_str]
                total_hosts = 1

        except ValueError:
            hosts = []
            total_hosts = 0

        return DryRunResult(
            target_subnet=target.target_subnet,
            total_hosts_in_scope=total_hosts,
            candidate_hosts=hosts[:10],
            ports_to_check=target.ports,
            network_operations_performed=0,
            execution_plan=(
                f"Dry-run for target "
                f"{target.target_subnet}: "
                f"{total_hosts} hosts in scope. "
                f"{len(target.ports)} defensive ports configured. "
                "Exactly 0 packets or sockets sent."
            ),
        )