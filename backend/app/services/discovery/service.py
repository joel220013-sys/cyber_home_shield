"""
Discovery Service orchestrator.

Responsibilities:
- Defensive target-scope validation
- Discovery provider selection
- Dry-run execution
- Live defensive discovery
- Device normalization
- Port normalization
- Database synchronization
- Scan-job status synchronization
- Per-user device ownership isolation
"""

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.core.security import validate_defensive_target_scope
from app.models import Device, OpenPort, ScanJob
from app.models.enums import DeviceType, ScanStatus
from app.schemas.device import DeviceCreate
from app.schemas.open_port import OpenPortCreate
from app.services.discovery.base import BaseDiscoveryProvider
from app.services.discovery.models import (
    DiscoveredHost,
    DiscoveredService,
    DiscoveryResult,
    DiscoveryTarget,
    DryRunResult,
)
from app.services.discovery.network_provider import (
    LiveNetworkDiscoveryProvider,
)


# ============================================================================
# DISCOVERY PROVIDER FACTORY
# ============================================================================


def get_default_discovery_provider() -> BaseDiscoveryProvider:
    """
    Return the configured discovery provider.

    Discovery mock mode has been permanently removed.

    Supported mode:
        network -> LiveNetworkDiscoveryProvider

    Any other value fails explicitly instead of silently returning
    fabricated/mock data.
    """

    provider_name = settings.DISCOVERY_PROVIDER.strip().lower()

    if provider_name == "network":
        return LiveNetworkDiscoveryProvider()

    raise ValueError(
        "Unsupported DISCOVERY_PROVIDER "
        f"{settings.DISCOVERY_PROVIDER!r}; "
        "only 'network' is supported."
    )


# ============================================================================
# DISCOVERY SERVICE
# ============================================================================


class DiscoveryService:
    """
    Master discovery service.

    Handles:

    - RFC1918 scope enforcement
    - Discovery provider execution
    - Dry-run mode
    - Device normalization
    - Port normalization
    - Database synchronization
    - Scan-job synchronization
    - User ownership isolation
    """

    def __init__(
        self,
        provider: Optional[BaseDiscoveryProvider] = None,
    ) -> None:
        """
        Initialize the discovery service.

        If no provider is explicitly supplied, the configured real
        discovery provider is selected.

        Discovery mock data is never used automatically.
        """

        self.provider = (
            provider
            if provider is not None
            else get_default_discovery_provider()
        )

    # ========================================================================
    # DEVICE NORMALIZATION
    # ========================================================================

    @staticmethod
    def normalize_host_to_device(
        host: DiscoveredHost,
    ) -> DeviceCreate:
        """
        Normalize a discovered host into DeviceCreate.

        Security rule:

        Do not fabricate:
        - vendor
        - operating system
        - model
        - device type

        Unknown attributes remain UNKNOWN.
        """

        return DeviceCreate(
            ip_address=host.ip_address,
            mac_address=host.mac_address or "",
            hostname=host.hostname or "",
            custom_name="",
            vendor="Unknown Vendor",
            device_type=DeviceType.UNKNOWN,
            is_trusted=False,
            is_online=host.is_online,
            risk_score=0.0,
        )

    # ========================================================================
    # SERVICE / PORT NORMALIZATION
    # ========================================================================

    @staticmethod
    def normalize_service_to_port(
        device_id: uuid.UUID,
        service: DiscoveredService,
    ) -> OpenPortCreate:
        """
        Normalize a discovered service into OpenPortCreate.
        """

        return OpenPortCreate(
            device_id=device_id,
            port_number=service.port,
            protocol=service.protocol,
            service_name=service.service_name or "unknown",
            banner=(
                service.evidence.raw_response
                if service.evidence
                else ""
            ),
            is_risky=False,
            risk_reason="",
        )

    @staticmethod
    def _is_stable_mac(mac: str) -> bool:
        """Only globally administered MACs may join inventory observations."""

        try:
            return bool(mac) and not (int(mac[:2], 16) & 0x02)
        except ValueError:
            return False

    @staticmethod
    def _host_evidence(host: DiscoveredHost) -> dict:
        """Persist only observed, non-sensitive discovery evidence."""

        def serialize(items):
            return [item.model_dump(mode="json") for item in items]

        return {
            "hostname": serialize(host.hostname_evidence),
            "vendor": serialize(host.vendor_evidence),
            "reachability": serialize(host.reachability_evidence),
        }

    @staticmethod
    def _identity_confidence(host: DiscoveredHost) -> str:
        if host.hostname and host.vendor:
            return "HIGH"
        if host.hostname or host.vendor or host.mac_address:
            return "MEDIUM"
        return "LOW"

    # ========================================================================
    # EXECUTE DISCOVERY
    # ========================================================================

    async def execute_discovery(
        self,
        target_str: str,
        ports: Optional[List[int]] = None,
        dry_run: bool = False,
        max_hosts: Optional[int] = None,
        local_ip: Optional[str] = None,
        db: Optional[AsyncSession] = None,
        scan_job_id: Optional[uuid.UUID] = None,
        owner_user_id: Optional[uuid.UUID] = None,
    ) -> Tuple[
        DiscoveryResult,
        Optional[DryRunResult],
    ]:
        """
        Validate scope and execute defensive discovery.

        Parameters:

        target_str:
            RFC1918 private IPv4 subnet or host.

        ports:
            Optional defensive port list.

        dry_run:
            If True, no network sockets are opened.

        max_hosts:
            Maximum number of hosts to inspect.

        db:
            Optional database session.

        scan_job_id:
            ScanJob associated with this discovery.

        owner_user_id:
            Authenticated user who owns this scan.

        Returns:

            (DiscoveryResult, DryRunResult | None)
        """

        # ====================================================================
        # 1. VALIDATE TARGET SCOPE
        # ====================================================================

        validate_defensive_target_scope(target_str)

        # ====================================================================
        # 2. BUILD DISCOVERY TARGET
        # ====================================================================

        target = DiscoveryTarget(
            target_subnet=target_str.strip(),
            ports=(
                ports
                if ports is not None
                else settings.DEFAULT_DISCOVERY_PORTS
            ),
            dry_run=dry_run,
            max_hosts=(
                max_hosts
                if max_hosts is not None
                else settings.MAX_HOSTS
            ),
            timeout_seconds=settings.DISCOVERY_TIMEOUT,
            local_ip=local_ip,
        )

        # ====================================================================
        # 3. DRY RUN
        # ====================================================================

        if dry_run:
            # The provider must perform ZERO network activity.
            dry_result = await self.provider.dry_run(target)

            now = datetime.now(timezone.utc)

            empty_result = DiscoveryResult(
                target=target.target_subnet,
                started_at=now,
                completed_at=now,
                hosts=[],
                services=[],
                evidence=[],
                errors=[],
            )

            # ---------------------------------------------------------------
            # Update ScanJob
            # ---------------------------------------------------------------

            if db is not None and scan_job_id is not None:
                job_query = select(ScanJob).where(
                    ScanJob.id == scan_job_id
                )

                job_res = await db.execute(job_query)

                scan_job = job_res.scalar_one_or_none()

                if scan_job:
                    scan_job.status = ScanStatus.COMPLETED
                    scan_job.devices_found = 0
                    scan_job.ports_scanned = 0
                    scan_job.completed_at = now
                    scan_job.error_message = ""

                    scan_job.summary_findings = {
                        "dry_run": True,
                        "target": target.target_subnet,
                        "hosts_discovered": 0,
                        "services_discovered": 0,
                        "statistics": dry_result.model_dump(),
                    }

                    await db.commit()

            return empty_result, dry_result

        # ====================================================================
        # 4. REAL DEFENSIVE DISCOVERY
        # ====================================================================

        result = await self.provider.discover(target)

        # ====================================================================
        # 5. DATABASE SYNCHRONIZATION
        # ====================================================================

        if db is not None:
            await self._sync_with_db(
                db=db,
                result=result,
                target=target,
                scan_job_id=scan_job_id,
                owner_user_id=owner_user_id,
            )

        return result, None

    # ========================================================================
    # DATABASE SYNCHRONIZATION
    # ========================================================================

    async def _sync_with_db(
        self,
        db: AsyncSession,
        result: DiscoveryResult,
        target: DiscoveryTarget,
        scan_job_id: Optional[uuid.UUID] = None,
        owner_user_id: Optional[uuid.UUID] = None,
    ) -> None:
        """
        Synchronize discovery results with the database.

        Ownership rules:

        Authenticated user:

            User A can only reuse User A's device records.

        Anonymous/global:

            Only unowned device records are reused.

        Important:

            A device owned by another user is never reused.
        """

        now = datetime.now(timezone.utc)

        # Remove open-port observations that were not present in this scan.
        # This keeps risk findings based on current observations rather than
        # indefinitely retaining ports from an earlier scan.
        target_network = ipaddress.ip_network(
            target.target_subnet.strip(),
            strict=False,
        )
        candidate_ips = {
            host.ip_address for host in result.hosts
        } | (
            {
                str(ip)
                for ip in list(target_network.hosts())[: target.max_hosts]
            }
            if "/" in target.target_subnet
            else {target.target_subnet.strip()}
        )

        scoped_devices_query = (
            select(Device)
            .options(selectinload(Device.ports))
        )

        if owner_user_id is not None:
            scoped_devices_query = scoped_devices_query.where(
                Device.user_id == owner_user_id
            )
        else:
            scoped_devices_query = scoped_devices_query.where(
                Device.user_id.is_(None)
            )

        scoped_devices_result = await db.execute(scoped_devices_query)
        scoped_devices = scoped_devices_result.scalars().all()
        currently_reachable_ips = {
            host.ip_address for host in result.hosts
        }

        # A completed scan is the current observation for this target. Keep
        # historical rows, but do not leave disconnected devices online.
        for scoped_device in scoped_devices:
            try:
                if ipaddress.ip_address(scoped_device.ip_address) in target_network:
                    scoped_device.is_online = (
                        scoped_device.ip_address in currently_reachable_ips
                    )
                else:
                    scoped_device.is_online = False
            except ValueError:
                continue

        current_services_by_ip = {
            host.ip_address: {
                (service.port, service.protocol)
                for service in host.services
            }
            for host in result.hosts
        }

        for scoped_device in scoped_devices:
            if scoped_device.ip_address not in candidate_ips:
                continue

            current_services = current_services_by_ip.get(
                scoped_device.ip_address,
                set(),
            )
            scoped_device.ports[:] = [
                port
                for port in scoped_device.ports
                if (port.port_number, port.protocol) in current_services
            ]

        # ====================================================================
        # SYNC HOSTS
        # ====================================================================

        for host in result.hosts:

            existing_device: Optional[Device] = None

            # =================================================================
            # AUTHENTICATED USER
            # =================================================================

            if owner_user_id is not None:

                owned_query = select(Device).where(
                    Device.ip_address == host.ip_address,
                    Device.user_id == owner_user_id,
                )

                owned_result = await db.execute(owned_query)

                existing_device = owned_result.scalar_one_or_none()

                # A globally administered MAC is stable identity evidence.
                # Reuse it when DHCP changes the address; never use a locally
                # administered/privacy MAC to merge separate devices.
                if existing_device is None and self._is_stable_mac(host.mac_address):
                    mac_result = await db.execute(
                        select(Device).where(
                            Device.mac_address == host.mac_address,
                            Device.user_id == owner_user_id,
                        )
                    )
                    existing_device = mac_result.scalar_one_or_none()

                # -------------------------------------------------------------
                # If no owned device exists, look for an unowned legacy
                # device with the same IP.
                #
                # This allows old devices created before ownership
                # enforcement to be claimed by the authenticated user.
                # -------------------------------------------------------------

                if existing_device is None:

                    global_query = select(Device).where(
                        Device.ip_address == host.ip_address,
                        Device.user_id.is_(None),
                    )

                    global_result = await db.execute(global_query)

                    global_device = global_result.scalar_one_or_none()

                    if global_device is not None:
                        global_device.user_id = owner_user_id
                        existing_device = global_device

            # =================================================================
            # ANONYMOUS / GLOBAL
            # =================================================================

            else:

                global_query = select(Device).where(
                    Device.ip_address == host.ip_address,
                    Device.user_id.is_(None),
                )

                global_result = await db.execute(global_query)

                existing_device = global_result.scalar_one_or_none()

            # =================================================================
            # UPDATE EXISTING DEVICE
            # =================================================================

            if existing_device:

                # -------------------------------------------------------------
                # Update MAC only if discovery has useful information.
                # -------------------------------------------------------------

                if (
                    host.mac_address
                    and not existing_device.mac_address
                ):
                    existing_device.mac_address = host.mac_address

                if existing_device.ip_address != host.ip_address and self._is_stable_mac(host.mac_address):
                    existing_device.ip_address = host.ip_address

                # -------------------------------------------------------------
                # Update hostname only when available.
                # -------------------------------------------------------------

                if (
                    host.hostname
                    and not existing_device.hostname
                ):
                    existing_device.hostname = host.hostname

                if host.vendor:
                    existing_device.vendor = host.vendor
                    existing_device.vendor_source = "ieee_oui_lookup"
                existing_device.identity_evidence = self._host_evidence(host)
                existing_device.identity_confidence = self._identity_confidence(host)

                # -------------------------------------------------------------
                # Update online state.
                # -------------------------------------------------------------

                existing_device.is_online = True
                existing_device.last_seen = now

                # -------------------------------------------------------------
                # Safety ownership assignment.
                # -------------------------------------------------------------

                if (
                    owner_user_id is not None
                    and existing_device.user_id is None
                ):
                    existing_device.user_id = owner_user_id

                device_id = existing_device.id

            # =================================================================
            # CREATE NEW DEVICE
            # =================================================================

            else:

                new_device = Device(
                    id=uuid.uuid4(),
                    user_id=owner_user_id,
                    ip_address=host.ip_address,
                    mac_address=host.mac_address or "",
                    hostname=host.hostname or "",
                    custom_name="",
                    vendor=host.vendor or "",
                    vendor_source=("ieee_oui_lookup" if host.vendor else ""),
                    device_role="",
                    identity_confidence=self._identity_confidence(host),
                    identity_evidence=self._host_evidence(host),
                    device_type=DeviceType.UNKNOWN,
                    is_trusted=False,
                    is_online=True,
                    risk_score=0.0,
                    first_seen=now,
                    last_seen=now,
                )

                db.add(new_device)

                # Ensure ID is available before creating ports.
                await db.flush()

                device_id = new_device.id

            # =================================================================
            # SYNC OPEN PORTS
            # =================================================================

            for service in host.services:

                port_query = select(OpenPort).where(
                    OpenPort.device_id == device_id,
                    OpenPort.port_number == service.port,
                    OpenPort.protocol == service.protocol,
                )

                port_result = await db.execute(port_query)

                existing_port = port_result.scalar_one_or_none()

                # =============================================================
                # UPDATE EXISTING PORT
                # =============================================================

                if existing_port:

                    if service.service_name:
                        existing_port.service_name = service.service_name

                    if service.evidence:
                        existing_port.banner = (
                            service.evidence.raw_response or ""
                        )

                # =============================================================
                # CREATE NEW PORT
                # =============================================================

                else:

                    new_port = OpenPort(
                        id=uuid.uuid4(),
                        device_id=device_id,
                        port_number=service.port,
                        protocol=service.protocol,
                        service_name=(
                            service.service_name or "unknown"
                        ),
                        banner=(
                            service.evidence.raw_response
                            if service.evidence
                            else ""
                        ),
                        is_risky=False,
                        risk_reason="",
                    )

                    db.add(new_port)

        # ====================================================================
        # UPDATE SCAN JOB
        # ====================================================================

        if scan_job_id is not None:

            job_query = select(ScanJob).where(
                ScanJob.id == scan_job_id
            )

            job_result = await db.execute(job_query)

            scan_job = job_result.scalar_one_or_none()

            if scan_job:

                scan_job.status = ScanStatus.COMPLETED

                scan_job.devices_found = len(result.hosts)

                scan_job.ports_scanned = (
                    result.statistics.services_checked
                )

                scan_job.completed_at = result.completed_at

                scan_job.error_message = ""

                scan_job.summary_findings = {
                    "hosts_discovered": len(result.hosts),
                    "services_discovered": len(result.services),
                    "statistics": result.statistics.model_dump(),
                }

        # ====================================================================
        # COMMIT
        # ====================================================================

        await db.commit()
