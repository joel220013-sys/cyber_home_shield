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
    ) -> Optional[DiscoveredHost]:
        """Audit a single host for reachability and configured open ports."""

        now = datetime.now(timezone.utc)
        mac = arp_table.get(ip_str, "")

        open_services = await self.port_profiler.scan_host_ports(
            ip_str,
            ports,
        )

        # A host is considered active when:
        # 1. At least one configured TCP service is open, or
        # 2. The host exists in the local ARP/neighbour table.
        if open_services or mac:
            hostname = await self.host_discoverer.resolve_hostname(
                ip_str
            )

            return DiscoveredHost(
                ip_address=ip_str,
                mac_address=mac,
                hostname=hostname,
                is_online=True,
                services=open_services,
                first_seen=now,
                last_seen=now,
                discovery_method="defensive_tcp_arp",
            )

        return None

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

        arp_table = self.host_discoverer.read_local_arp_table()

        logger.debug(
            "Read %d private hosts from local ARP table.",
            len(arp_table),
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

                candidate_ips = [
                    str(ip)
                    for ip in list(network.hosts())[: target.max_hosts]
                ]
            else:
                candidate_ips = [target_str]

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

        semaphore = asyncio.Semaphore(
            settings.MAX_CONCURRENT_CHECKS
        )

        async def bounded_audit(
            ip: str,
        ) -> Optional[DiscoveredHost]:
            async with semaphore:
                try:
                    return await self._audit_host(
                        ip,
                        target.ports,
                        arp_table,
                    )

                except Exception as exc:
                    logger.debug(
                        "Error auditing host %s: %s",
                        ip,
                        exc,
                    )
                    return None

        tasks = [
            bounded_audit(ip)
            for ip in candidate_ips
        ]

        results = await asyncio.gather(
            *tasks,
            return_exceptions=False,
        )

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
                        f"Audited {len(candidate_ips)} candidates "
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
                    len(candidate_ips)
                    * len(target.ports)
                ),
                services_found=len(all_services),
                duration_seconds=round(
                    duration,
                    3,
                ),
            ),
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