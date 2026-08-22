"""
Aggregates defensive security findings from observed ports and anomalies.

This module converts deterministic observations into persisted-compatible
security findings.

Important:
    Deterministic security classification takes precedence over stale or
    incomplete `is_risky` metadata for security-relevant ports.
"""

import uuid
from typing import Any, List

from app.models.enums import FindingStatus, Severity
from app.services.risk_engine.models import (
    AnomalyResult,
    BaselineStatus,
    EvaluatedFinding,
    FindingCategory,
    FindingEvidence,
)


class FindingAggregator:
    """Generate substantiated defensive security findings."""

    # ========================================================================
    # DETERMINISTIC RISKY PORTS
    # ========================================================================

    # These ports have explicit finding rules below.
    #
    # We intentionally do NOT allow a persisted `is_risky=False` value to
    # suppress these findings. The scanner metadata may be stale or may
    # represent exposure differently from the risk engine.
    DETERMINISTIC_RISKY_PORTS = {
        22,
        80,
        445,
        554,
        8080,
    }

    # ========================================================================
    # PORT FINDINGS
    # ========================================================================

    @staticmethod
    def generate_findings_from_ports(
        device_id: uuid.UUID,
        open_ports: List[Any],
    ) -> List[EvaluatedFinding]:
        """
        Generate deterministic security findings from observed open ports.

        Supported input types:

        1. Integer:
               80

        2. ORM/schema object:
               object.port_number
               object.is_risky

        3. Dictionary:
               {
                   "port_number": 80,
                   "is_risky": False
               }

        Security-relevant ports are classified deterministically.

        Therefore:

            port 80 + is_risky=False
                -> HTTP finding IS generated

            port 554 + is_risky=False
                -> RTSP finding IS generated

        This prevents stale scanner metadata from suppressing risk findings.
        """

        findings: List[EvaluatedFinding] = []

        # ====================================================================
        # NORMALIZE PORTS
        # ====================================================================

        normalized_ports: dict[int, bool] = {}

        for item in open_ports:

            port = None
            explicit_is_risky = None

            # ----------------------------------------------------------------
            # Integer input
            # ----------------------------------------------------------------

            if isinstance(item, int):
                port = item

            # ----------------------------------------------------------------
            # ORM / schema object
            # ----------------------------------------------------------------

            elif hasattr(item, "port_number"):
                port = getattr(
                    item,
                    "port_number",
                    None,
                )

                explicit_is_risky = getattr(
                    item,
                    "is_risky",
                    None,
                )

            # ----------------------------------------------------------------
            # Dictionary input
            # ----------------------------------------------------------------

            elif isinstance(item, dict):
                port = item.get("port_number")

                explicit_is_risky = item.get(
                    "is_risky"
                )

            # ----------------------------------------------------------------
            # Ignore invalid entries
            # ----------------------------------------------------------------

            if port is None:
                continue

            try:
                port = int(port)
            except (TypeError, ValueError):
                continue

            # =================================================================
            # DETERMINISTIC CLASSIFICATION
            # =================================================================

            if port in FindingAggregator.DETERMINISTIC_RISKY_PORTS:
                """
                Security-relevant ports are always evaluated by the
                deterministic finding engine.

                This is the important fix.

                Example:

                    database:
                        port = 554
                        is_risky = False

                    deterministic engine:
                        554 is a known RTSP service

                    result:
                        is_risky = True
                """

                is_risky = True

            elif explicit_is_risky is not None:
                """
                For ports without a dedicated deterministic finding rule,
                preserve explicit scanner metadata.
                """

                is_risky = bool(
                    explicit_is_risky
                )

            else:
                is_risky = False

            normalized_ports[port] = is_risky

        # ====================================================================
        # GENERATE FINDINGS
        # ====================================================================

        for port in sorted(normalized_ports):

            is_risky = normalized_ports[port]

            if not is_risky:
                continue

            # ================================================================
            # PORT 445 - SMB
            # ================================================================

            if port == 445:

                evidence = FindingEvidence(
                    source="open_port",
                    port=445,
                    protocol="TCP",
                    reason=(
                        "SMB file sharing service active "
                        "on local subnet"
                    ),
                    raw_data="TCP 445 OPEN",
                )

                findings.append(
                    EvaluatedFinding(
                        device_id=device_id,
                        title=(
                            "SMB File Sharing Service Exposed"
                        ),
                        category=(
                            FindingCategory.EXPOSURE.value
                        ),
                        severity=Severity.HIGH,
                        status=FindingStatus.OPEN,
                        description=(
                            "Server Message Block (SMB) service "
                            "is accessible on TCP port 445. "
                            "Unrestricted SMB exposure on local "
                            "subnets presents a risk of "
                            "unauthorized file access and "
                            "lateral movement."
                        ),
                        evidence=evidence.model_dump(
                            mode="json"
                        ),
                        remediation_steps=(
                            "1. Disable SMBv1 and enable SMB signing.\n"
                            "2. Restrict SMB access to authorized "
                            "IP subnets.\n"
                            "3. Ensure strong authentication on "
                            "all shared folders."
                        ),
                    )
                )

            # ================================================================
            # PORT 80 - HTTP
            # ================================================================

            elif port == 80:

                evidence = FindingEvidence(
                    source="open_port",
                    port=80,
                    protocol="TCP",
                    reason=(
                        "Unencrypted HTTP web management "
                        "interface observed"
                    ),
                    raw_data="TCP 80 OPEN",
                )

                findings.append(
                    EvaluatedFinding(
                        device_id=device_id,
                        title=(
                            "Unencrypted HTTP "
                            "Management Interface Exposed"
                        ),
                        category=(
                            FindingCategory.EXPOSURE.value
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                        description=(
                            "An unencrypted HTTP web server is "
                            "active on TCP port 80. Credentials "
                            "and session cookies transmitted over "
                            "plaintext HTTP can be intercepted on "
                            "the local network."
                        ),
                        evidence=evidence.model_dump(
                            mode="json"
                        ),
                        remediation_steps=(
                            "1. Redirect all HTTP traffic to HTTPS "
                            "(port 443).\n"
                            "2. Enable TLS/SSL certificates for "
                            "the management console.\n"
                            "3. Disable plain HTTP administration "
                            "if HTTPS is available."
                        ),
                    )
                )

            # ================================================================
            # PORT 554 - RTSP
            # ================================================================

            elif port == 554:

                evidence = FindingEvidence(
                    source="open_port",
                    port=554,
                    protocol="TCP",
                    reason=(
                        "RTSP media streaming service "
                        "observed on port 554"
                    ),
                    raw_data="TCP 554 OPEN",
                )

                findings.append(
                    EvaluatedFinding(
                        device_id=device_id,
                        title=(
                            "RTSP Video Streaming "
                            "Service Exposed"
                        ),
                        category=(
                            FindingCategory.EXPOSURE.value
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                        description=(
                            "Real Time Streaming Protocol (RTSP) "
                            "is active on TCP port 554. If weak, "
                            "default, or missing authentication "
                            "is used, video streams may be "
                            "accessible to unauthorized devices "
                            "on the network."
                        ),
                        evidence=evidence.model_dump(
                            mode="json"
                        ),
                        remediation_steps=(
                            "1. Enforce strong RTSP authentication.\n"
                            "2. Change default camera credentials.\n"
                            "3. Place IP cameras on an isolated "
                            "IoT VLAN.\n"
                            "4. Restrict RTSP access to authorized "
                            "hosts.\n"
                            "5. Use encrypted RTSP/TLS if supported "
                            "by the camera firmware."
                        ),
                    )
                )

            # ================================================================
            # PORT 22 - SSH
            # ================================================================

            elif port == 22:

                evidence = FindingEvidence(
                    source="open_port",
                    port=22,
                    protocol="TCP",
                    reason=(
                        "SSH remote management "
                        "service active"
                    ),
                    raw_data="TCP 22 OPEN",
                )

                findings.append(
                    EvaluatedFinding(
                        device_id=device_id,
                        title=(
                            "SSH Remote Administrative "
                            "Interface Active"
                        ),
                        category=(
                            FindingCategory.SERVICE.value
                        ),
                        severity=Severity.LOW,
                        status=FindingStatus.OPEN,
                        description=(
                            "SSH remote management console is "
                            "listening on port 22. While encrypted, "
                            "SSH interfaces should enforce "
                            "strong authentication and restrict "
                            "access to trusted management hosts."
                        ),
                        evidence=evidence.model_dump(
                            mode="json"
                        ),
                        remediation_steps=(
                            "1. Disable password authentication "
                            "in favor of ED25519 SSH keys.\n"
                            "2. Set 'PermitRootLogin no' in "
                            "sshd_config.\n"
                            "3. Restrict SSH access to trusted "
                            "management IP addresses.\n"
                            "4. Keep the SSH service updated."
                        ),
                    )
                )

            # ================================================================
            # PORT 8080 - HTTP ALTERNATE
            # ================================================================

            elif port == 8080:

                evidence = FindingEvidence(
                    source="open_port",
                    port=8080,
                    protocol="TCP",
                    reason=(
                        "HTTP alternate unencrypted "
                        "port active"
                    ),
                    raw_data="TCP 8080 OPEN",
                )

                findings.append(
                    EvaluatedFinding(
                        device_id=device_id,
                        title=(
                            "Unencrypted Secondary "
                            "Web Service (Port 8080)"
                        ),
                        category=(
                            FindingCategory.EXPOSURE.value
                        ),
                        severity=Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                        description=(
                            "A secondary unencrypted web interface "
                            "was discovered on port 8080. Secondary "
                            "web consoles may expose administrative "
                            "or debugging endpoints."
                        ),
                        evidence=evidence.model_dump(
                            mode="json"
                        ),
                        remediation_steps=(
                            "1. Verify whether port 8080 "
                            "requires LAN exposure.\n"
                            "2. Enforce authentication.\n"
                            "3. Disable the service if unnecessary.\n"
                            "4. Migrate administrative access "
                            "to an authenticated TLS endpoint."
                        ),
                    )
                )

        return findings

    # ========================================================================
    # ANOMALY FINDINGS
    # ========================================================================

    @staticmethod
    def generate_findings_from_anomalies(
        device_id: uuid.UUID,
        anomaly_result: AnomalyResult,
    ) -> List[EvaluatedFinding]:
        """
        Generate security findings for high-risk or severe anomalies.
        """

        findings: List[EvaluatedFinding] = []

        # ====================================================================
        # Only anomalous states create findings
        # ====================================================================

        if anomaly_result.status not in (
            BaselineStatus.ANOMALOUS,
            BaselineStatus.SEVERE_ANOMALY,
        ):
            return findings

        # ====================================================================
        # Determine severity
        # ====================================================================

        severity = (
            Severity.CRITICAL
            if anomaly_result.status
            == BaselineStatus.SEVERE_ANOMALY
            else Severity.HIGH
        )

        # ====================================================================
        # Build evidence
        # ====================================================================

        evidence = FindingEvidence(
            source="anomaly_detector",
            reason=(
                "Telemetry anomaly detected with score "
                f"{anomaly_result.anomaly_score}/100"
            ),
            raw_data=(
                f"Status: {anomaly_result.status.value}, "
                f"Anomaly Count: "
                f"{len(anomaly_result.anomalies_detected)}"
            ),
        )

        # ====================================================================
        # Build human-readable anomaly summary
        # ====================================================================

        reasons_summary = "\n".join(
            (
                f"- {anomaly.get('reason', 'Anomaly event')}"
                for anomaly
                in anomaly_result.anomalies_detected
            )
        )

        if not reasons_summary:
            reasons_summary = (
                "- No detailed anomaly reason provided."
            )

        # ====================================================================
        # Create anomaly finding
        # ====================================================================

        findings.append(
            EvaluatedFinding(
                device_id=device_id,
                title=(
                    "Network Telemetry Anomaly Detected "
                    f"({anomaly_result.status.value.upper()})"
                ),
                category=FindingCategory.ANOMALY.value,
                severity=severity,
                status=FindingStatus.OPEN,
                description=(
                    "Deterministic baseline telemetry analysis "
                    "flagged anomalous behavior on this device.\n"
                    f"Identified indicators:\n"
                    f"{reasons_summary}"
                ),
                evidence=evidence.model_dump(
                    mode="json"
                ),
                remediation_steps=(
                    "1. Inspect active processes and outbound "
                    "network connections on the device.\n"
                    "2. Check for unauthorized background "
                    "services or compromised firmware.\n"
                    "3. Review recent device telemetry and "
                    "authentication events.\n"
                    "4. Temporarily isolate the device from "
                    "sensitive network segments if anomalous "
                    "behavior persists."
                ),
            )
        )

        return findings