"""Honeypot Event Persistence, Anomaly Detection, and Security Finding Integration."""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import FindingStatus, Severity
from app.models.honeypot_event import HoneypotEvent
from app.models.network_event import NetworkEvent
from app.models.security_finding import SecurityFinding
from app.models.device import Device
from app.services.honeypot.base import HoneypotTelemetryEvent
from app.services.honeypot.isolation import sanitize_metadata


logger = logging.getLogger("cyber_shield.honeypot.logger")


class HoneypotAnomalyTracker:
    """In-memory sliding-window tracker for deterministic honeypot anomaly detection."""

    def __init__(self) -> None:
        # Key:
        # (user_id, source_ip, interaction_type) -> timestamps
        self._history: Dict[
            Tuple[str, str, str],
            List[datetime],
        ] = defaultdict(list)

    def record_and_evaluate(
        self,
        source_ip: str,
        interaction_type: str,
        timestamp: datetime,
        user_id: Optional[uuid.UUID] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Record interaction and check deterministic anomaly thresholds.

        Thresholds:
        - Repeated login attempts: >= 5 in 60 seconds -> HIGH
        - Repeated admin endpoint accesses: >= 3 in 60 seconds -> HIGH
        - Connection flooding: >= 10 in 30 seconds -> CRITICAL
        """

        user_key = str(user_id) if user_id else "global"

        key = (
            user_key,
            source_ip,
            interaction_type,
        )

        now = timestamp or datetime.now(timezone.utc)

        # Keep only the previous 2 minutes.
        cutoff = now - timedelta(seconds=120)

        history = [
            ts
            for ts in self._history[key]
            if ts > cutoff
        ]

        history.append(now)

        self._history[key] = history

        # -------------------------------------------------
        # 1. Repeated login attempts
        # -------------------------------------------------

        if interaction_type in (
            "login_attempt",
            "auth_attempt",
        ):
            recent_logins = [
                ts
                for ts in history
                if ts > now - timedelta(seconds=60)
            ]

            if len(recent_logins) >= 5:
                return {
                    "anomaly_type": "repeated_login_attempts",
                    "title": (
                        "Repeated Simulated Login Attempts "
                        "on Honeypot Decoy"
                    ),
                    "severity": Severity.HIGH,
                    "count": len(recent_logins),
                    "window_seconds": 60,
                    "description": (
                        f"Detected {len(recent_logins)} rapid "
                        f"authentication attempts targeting "
                        f"honeypot from source IP {source_ip} "
                        f"within 60 seconds."
                    ),
                    "remediation": (
                        "Investigate internal client at source IP "
                        "for malware or unauthorized automated "
                        "scanning."
                    ),
                }

        # -------------------------------------------------
        # 2. Repeated administrative endpoint probing
        # -------------------------------------------------

        if interaction_type in (
            "admin_endpoint_access",
            "suspicious_request",
        ):
            recent_admin = [
                ts
                for ts in history
                if ts > now - timedelta(seconds=60)
            ]

            if len(recent_admin) >= 3:
                return {
                    "anomaly_type": "repeated_admin_access",
                    "title": (
                        "Repeated Administrative Endpoint "
                        "Probing on Honeypot Decoy"
                    ),
                    "severity": Severity.HIGH,
                    "count": len(recent_admin),
                    "window_seconds": 60,
                    "description": (
                        f"Detected {len(recent_admin)} "
                        f"administrative endpoint probe requests "
                        f"targeting honeypot from source IP "
                        f"{source_ip} within 60 seconds."
                    ),
                    "remediation": (
                        "Check device authorization and isolate "
                        "source host if unrecognized."
                    ),
                }

        # -------------------------------------------------
        # 3. Connection flooding
        # -------------------------------------------------

        conn_key = (
            user_key,
            source_ip,
            "any",
        )

        all_conns = [
            ts
            for ts in self._history[conn_key]
            if ts > now - timedelta(seconds=30)
        ]

        all_conns.append(now)

        self._history[conn_key] = all_conns

        if len(all_conns) >= 10:
            return {
                "anomaly_type": "unusual_connection_frequency",
                "title": (
                    "Abnormal Connection Frequency Detected "
                    "on Honeypot Decoy"
                ),
                "severity": Severity.CRITICAL,
                "count": len(all_conns),
                "window_seconds": 30,
                "description": (
                    f"Excessive connection burst of "
                    f"{len(all_conns)} requests to honeypot "
                    f"decoy from source IP {source_ip} "
                    f"within 30 seconds."
                ),
                "remediation": (
                    "Potential aggressive network scanner or "
                    "compromised host. Check firewall rules."
                ),
            }

        return None


# Global deterministic tracker
honeypot_anomaly_tracker = HoneypotAnomalyTracker()


async def log_honeypot_event(
    db: AsyncSession,
    telemetry: HoneypotTelemetryEvent,
) -> HoneypotEvent:
    """
    Persist sanitized honeypot telemetry and generate a
    SecurityFinding when a deterministic anomaly is detected.

    Device association is resolved using source IP within the
    event owner's tenant. Unowned telemetry can only correlate
    with an unowned device.
    """

    # ---------------------------------------------------------
    # 1. Sanitize metadata
    # ---------------------------------------------------------

    clean_metadata = sanitize_metadata(
        telemetry.metadata_fields
    )

    # ---------------------------------------------------------
    # 2. Persist honeypot event
    # ---------------------------------------------------------

    event_record = HoneypotEvent(
        id=uuid.uuid4(),
        user_id=telemetry.user_id,
        event_timestamp=telemetry.event_timestamp,
        honeypot_id=telemetry.honeypot_id,
        source_ip=telemetry.source_ip,
        source_port=telemetry.source_port,
        destination_port=telemetry.destination_port,
        protocol=telemetry.protocol,
        interaction_type=telemetry.interaction_type,
        endpoint=telemetry.endpoint,
        user_agent=telemetry.user_agent,
        payload_sample=telemetry.payload_sample,
        metadata_fields=clean_metadata,
        severity=telemetry.severity,
    )

    db.add(event_record)

    network_event = NetworkEvent(
        id=uuid.uuid4(),
        device_id=None,
        user_id=telemetry.user_id,
        event_timestamp=telemetry.event_timestamp,
        source_ip=telemetry.source_ip,
        destination_ip=telemetry.destination_ip,
        source_port=telemetry.source_port,
        destination_port=telemetry.destination_port,
        protocol=telemetry.protocol,
        bytes_transferred=0,
    )

    db.add(network_event)

    # ---------------------------------------------------------
    # 3. Run deterministic anomaly detection
    # ---------------------------------------------------------

    anomaly = honeypot_anomaly_tracker.record_and_evaluate(
        source_ip=telemetry.source_ip,
        interaction_type=telemetry.interaction_type,
        timestamp=telemetry.event_timestamp,
        user_id=telemetry.user_id,
    )

    if anomaly:
        network_event.is_anomaly = True
        network_event.anomaly_reason = anomaly["description"]
        network_event.severity = anomaly["severity"]

    # ---------------------------------------------------------
    # 4. Generate security finding if anomaly detected
    # ---------------------------------------------------------

    if anomaly:

        dev_stmt = select(Device).where(
            Device.ip_address == telemetry.source_ip,
            Device.user_id == telemetry.user_id,
        )

        dev_res = await db.execute(dev_stmt)

        device = dev_res.scalars().first()

        # SecurityFinding.device_id is NOT NULL.
        # Therefore, never create a finding without a device.
        if device is None:
            logger.warning(
                "Honeypot anomaly detected from unregistered "
                "source IP %s; no Device record exists.",
                telemetry.source_ip,
            )

            # Preserve the telemetry event.
            await db.commit()
            await db.refresh(event_record)

            return event_record

        # -----------------------------------------------------
        # 5. Build evidence payload
        # -----------------------------------------------------

        evidence_payload = {
            "source": "honeypot",
            "honeypot_id": telemetry.honeypot_id,
            "interaction": telemetry.interaction_type,
            "attempt_count": anomaly["count"],
            "window_seconds": anomaly["window_seconds"],
            "source_ip": telemetry.source_ip,
            "target_port": telemetry.destination_port,
        }

        # -----------------------------------------------------
        # 6. Create SecurityFinding
        # -----------------------------------------------------

        finding_record = SecurityFinding(
            id=uuid.uuid4(),
            device_id=device.id,
            title=anomaly["title"],
            category="Honeypot Deception Telemetry",
            severity=anomaly["severity"],
            status=FindingStatus.OPEN,
            description=anomaly["description"],
            evidence=evidence_payload,
            remediation_steps=anomaly["remediation"],
        )

        db.add(finding_record)

        logger.warning(
            "Honeypot anomaly detected -> "
            "generated %s finding '%s' "
            "for device %s",
            anomaly["severity"],
            finding_record.title,
            device.id,
        )

    # ---------------------------------------------------------
    # 7. Commit event + finding
    # ---------------------------------------------------------

    await db.commit()

    await db.refresh(event_record)

    return event_record