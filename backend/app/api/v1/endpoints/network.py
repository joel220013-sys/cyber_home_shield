"""Authenticated local network detection and discovery endpoints."""

import asyncio
import ipaddress
import uuid
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.models.device import Device
from app.models.honeypot_event import HoneypotEvent
from app.models.enums import FindingStatus, Severity
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.network import RouterDetectionResponse
from app.schemas.network_health import RouterHealthResponse
from app.schemas.network_discovery import (
    DiscoveredNetworkDevice,
    NetworkDiscoveryRequest,
    NetworkDiscoveryResponse,
    PostureEvidence,
)
from app.services.discovery.service import DiscoveryService
from app.services.discovery.arp_scanner import SafeHostDiscoverer
from app.config import settings
from app.core.exceptions import ScopeValidationError
from app.services.network import LocalNetworkDetector
from app.services.risk_engine.calculator import RiskCalculator

router = APIRouter(prefix="/network", tags=["Local Network"])


@router.get(
    "/router",
    response_model=RouterDetectionResponse,
    summary="Detect local default gateway",
)
async def detect_router(
    current_user: User = Depends(get_current_user),
) -> RouterDetectionResponse:
    """Detect the network of the machine running the Cyber Home Shield backend.

    This is local, read-only route inspection. It does not authenticate with,
    configure, scan, or otherwise contact the detected gateway.
    """
    return LocalNetworkDetector().detect()


@router.get(
    "/router/health",
    response_model=RouterHealthResponse,
    summary="Check reachability of the detected local gateway",
)
async def check_router_health(
    current_user: User = Depends(get_current_user),
) -> RouterHealthResponse:
    """Check only the locally detected gateway with one short ICMP probe."""
    return LocalNetworkDetector().check_gateway_health()


@router.post(
    "/devices/discover",
    response_model=NetworkDiscoveryResponse,
    summary="Discover devices on the detected authorized local network",
)
async def discover_local_devices(
    request: NetworkDiscoveryRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> NetworkDiscoveryResponse:
    """Discover only the network CIDR detected on the backend machine.

    The request has no target parameter. The existing bounded discovery
    provider is reused, and results are owned by the authenticated user.
    """
    detection = LocalNetworkDetector().detect()
    network = detection.network_cidr
    if detection.status != "detected" or not network:
        return NetworkDiscoveryResponse(status="unavailable", devices=[])

    try:
        detected_network = ipaddress.ip_network(network, strict=False)
        authorized_network = ipaddress.ip_network(
            current_user.authorized_network_scope,
            strict=False,
        )
        if detected_network.version != 4 or not detected_network.subnet_of(authorized_network):
            return NetworkDiscoveryResponse(
                status="unavailable",
                network=network,
                devices=[],
            )
    except (ValueError, TypeError):
        return NetworkDiscoveryResponse(
            status="unavailable",
            network=network,
            devices=[],
        )

    service = DiscoveryService()
    try:
        result, _ = await asyncio.wait_for(
            service.execute_discovery(
                target_str=network,
                db=db,
                owner_user_id=current_user.id,
                max_hosts=min(settings.MAX_HOSTS, 254),
                local_ip=detection.local_ip,
            ),
            timeout=settings.DISCOVERY_TIMEOUT,
        )
    except (asyncio.TimeoutError, ScopeValidationError, ValueError):
        return NetworkDiscoveryResponse(
            status="unavailable",
            network=network,
            devices=[],
        )

    devices = [
        await _posture_device(
            host,
            db=db,
            user_id=current_user.id,
            detection=detection,
        )
        for host in result.hosts
    ]
    return NetworkDiscoveryResponse(
        status="completed",
        network=network,
        devices=devices,
    )


async def _posture_device(
    host,
    db: AsyncSession,
    user_id: uuid.UUID,
    detection,
) -> DiscoveredNetworkDevice:
    """Build posture identity and risk state from observed local evidence."""

    gateway_ip = detection.gateway_ip
    vendor = (
        host.vendor
        or SafeHostDiscoverer.mac_vendor_label(host.mac_address)
        or None
    )
    if vendor == "Privacy-randomized MAC":
        vendor = None
    mac_type = "unknown"
    if host.mac_address:
        first_octet = int(host.mac_address[:2], 16)
        mac_type = (
            "locally_administered"
            if first_octet & 0x02
            else "globally_administered"
        )

    has_identity = bool(
        host.hostname
        or (vendor and vendor != "Privacy-randomized MAC")
        or host.ip_address == gateway_ip
        or host.ip_address == detection.dhcp_server_ip
        or host.ip_address in detection.dns_server_ips
    )

    device_result = await db.execute(
        select(Device)
        .where(Device.ip_address == host.ip_address, Device.user_id == user_id)
        .options(
            selectinload(Device.ports),
            selectinload(Device.findings),
            selectinload(Device.events),
        )
    )
    device = device_result.scalar_one_or_none()
    honeypot_result = await db.execute(
        select(HoneypotEvent).where(
            HoneypotEvent.source_ip == host.ip_address,
            HoneypotEvent.user_id == user_id,
        )
    )
    honeypot_events = honeypot_result.scalars().all()

    findings = list(device.findings) if device else []
    events = list(device.events) if device else []
    active_findings = [
        finding for finding in findings
        if finding.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
    ]
    risk_result = (
        RiskCalculator.calculate_device_risk(
            device_id=device.id,
            open_ports=list(device.ports),
            events=events,
            existing_findings=active_findings,
        )
        if device else None
    )

    evidence: list[str] = []
    posture_evidence: list[PostureEvidence] = []
    device_role = "Unknown"
    if host.ip_address == gateway_ip:
        device_role = "Gateway/Router"
        evidence.append("identified as network gateway")
        posture_evidence.append(PostureEvidence(category="role", source="default_gateway_route", detail="IP matches the default gateway reported by the backend host routing table."))
        if host.mac_address:
            posture_evidence.append(PostureEvidence(category="role", source="arp_neighbor_relationship", detail="Gateway IP has a MAC mapping from the local ARP/neighbor table."))
    elif host.ip_address == detection.dhcp_server_ip:
        device_role = "DHCP server"
        posture_evidence.append(PostureEvidence(category="role", source="dhcp_configuration", detail="IP matches the DHCP server reported by the active local adapter."))
    elif host.ip_address in detection.dns_server_ips:
        device_role = "DNS server"
        posture_evidence.append(PostureEvidence(category="role", source="dns_configuration", detail="IP matches a DNS server reported by the active local adapter."))
    evidence.append("observed in authorized network scope")
    posture_evidence.append(PostureEvidence(category="identity", source="authorized_cidr", detail="IP is within the detected network and the authenticated user's authorized CIDR."))
    if host.is_online:
        evidence.append("reachable")
    for item in host.hostname_evidence:
        posture_evidence.append(PostureEvidence(category="hostname", source=item.method, detail=item.raw_response))
    if host.hostname:
        evidence.append(f"hostname resolved: {host.hostname}")
    for item in host.vendor_evidence:
        posture_evidence.append(PostureEvidence(category="vendor", source=item.method, detail=item.raw_response))
    if vendor and vendor != "Privacy-randomized MAC":
        evidence.append(f"vendor identified: {vendor}")
    for item in host.reachability_evidence:
        posture_evidence.append(PostureEvidence(category="reachability", source=item.method, detail=item.raw_response))
    if host.is_online and not host.reachability_evidence:
        posture_evidence.append(PostureEvidence(category="reachability", source="discovery_result", detail="Host was returned as reachable by the bounded discovery provider."))
    for service in host.services:
        evidence.append(f"observed open service on TCP/{service.port}")
    for event in events:
        if event.is_anomaly:
            evidence.append(f"anomalous telemetry: {event.anomaly_reason}")
            posture_evidence.append(PostureEvidence(category="security", source="anomalous_telemetry", detail=event.anomaly_reason or "Telemetry event is marked anomalous."))
    for finding in active_findings:
        evidence.append(f"active security finding: {finding.title}")
        posture_evidence.append(PostureEvidence(category="security", source="active_security_finding", detail=f"{finding.severity.value}: {finding.title}"))
    for event in honeypot_events:
        evidence.append(f"honeypot interaction: {event.interaction_type}")
        posture_evidence.append(PostureEvidence(category="security", source="honeypot_interaction", detail=f"Observed {event.interaction_type} against {event.honeypot_id}."))

    suspicious_findings = [
        finding for finding in active_findings
        if finding.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    suspicious_events = [event for event in events if event.is_anomaly]
    has_suspicious_evidence = bool(
        suspicious_findings or suspicious_events or honeypot_events
    )
    signal_count = sum(bool(signal) for signal in (
        suspicious_findings, suspicious_events, honeypot_events
    ))
    classification = "SUSPICIOUS" if has_suspicious_evidence else (
        "KNOWN" if has_identity else "UNIDENTIFIED"
    )
    confidence = "HIGH" if signal_count >= 2 or (has_identity and not has_suspicious_evidence) else "MEDIUM"
    risk_score = risk_result.overall_score if risk_result else 0.0
    risk_level = (
        "CRITICAL" if risk_score >= 80 else
        "HIGH" if risk_score >= 60 else
        "MEDIUM" if risk_score >= 30 else
        "LOW"
    )
    reason = (
        "Multiple independent security signals correlate to suspicious activity"
        if signal_count >= 2 else
        "Security-relevant evidence observed"
        if has_suspicious_evidence else
        "No suspicious security evidence observed"
    )
    evidence_state = (
        "Security evidence correlated"
        if has_suspicious_evidence
        else "Hostname unavailable; checked local resolver sources returned no result"
        if not host.hostname
        else "Identity metadata available"
    )

    return DiscoveredNetworkDevice(
        ip=host.ip_address,
        mac=host.mac_address or None,
        hostname=host.hostname or None,
        vendor=vendor,
        status="reachable" if host.is_online else "unreachable",
        mac_type=mac_type,
        classification=classification,
        identity_classification=classification,
        evidence_state=evidence_state,
        risk_level=risk_level,
        risk_score=round(risk_score, 2),
        confidence=confidence,
        evidence=evidence,
        reason=reason,
        device_role=device_role,
        posture_evidence=posture_evidence,
    )
