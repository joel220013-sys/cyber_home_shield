"""
Deterministic baseline anomaly detection on network telemetry events.

This module performs defensive, rule-based telemetry analysis.

It does not perform exploitation, scanning, credential attacks,
or other offensive actions.
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.services.risk_engine.models import (
    AnomalyBaseline,
    AnomalyResult,
    BaselineStatus,
)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Minimum number of telemetry events required to establish a baseline.
MIN_EVENTS_FOR_BASELINE = 5


# Common destination/service ports expected in a home network.
STANDARD_HOME_PORTS = {
    22,
    53,
    67,
    68,
    80,
    123,
    443,
    445,
    554,
    631,
    8080,
    8443,
}


# Protocol values considered unusual for this deterministic detector.
UNCOMMON_PROTOCOLS = {
    "OTHER",
    "RAW",
    "ICMP",
}


class BaselineAnomalyDetector:
    """
    Deterministic, rule-driven network telemetry anomaly detector.

    Detection categories:

        1. Explicit anomaly flags
        2. Repeated external destination
        3. Unusual destination ports
        4. Event-rate bursts
        5. Uncommon protocols

    The detector produces a score from 0-100.
    """

    # ========================================================================
    # NORMALIZATION HELPERS
    # ========================================================================

    @staticmethod
    def _get_value(
        event: Any,
        field: str,
        default: Any = None,
    ) -> Any:
        """
        Read a field from either an ORM/schema object or dictionary.
        """

        if isinstance(event, dict):
            return event.get(field, default)

        return getattr(
            event,
            field,
            default,
        )

    # ------------------------------------------------------------------------

    @staticmethod
    def _normalize_port(
        value: Any,
    ) -> int | None:
        """
        Convert a destination port to a valid integer.
        """

        if value is None:
            return None

        try:
            port = int(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

        if not 1 <= port <= 65535:
            return None

        return port

    # ------------------------------------------------------------------------

    @staticmethod
    def _normalize_protocol(
        value: Any,
    ) -> str:
        """
        Normalize protocol values.

        Supports enums such as:

            Protocol.TCP

        and strings such as:

            "TCP"
            "tcp"
            "ICMP"
        """

        if value is None:
            return "UNKNOWN"

        # Enum-like values.
        enum_value = getattr(
            value,
            "value",
            None,
        )

        if enum_value is not None:
            value = enum_value

        normalized = str(
            value
        ).strip().upper()

        if not normalized:
            return "UNKNOWN"

        return normalized

    # ------------------------------------------------------------------------

    @staticmethod
    def _normalize_timestamp(
        value: Any,
    ) -> datetime | None:
        """
        Normalize telemetry timestamps.

        Naive timestamps are interpreted as UTC.

        Timezone-aware timestamps are converted to UTC.

        This prevents subtraction errors caused by mixing:

            naive datetime

        with:

            timezone-aware datetime.
        """

        if value is None:
            return None

        # ---------------------------------------------------------------
        # Already a datetime
        # ---------------------------------------------------------------

        if isinstance(
            value,
            datetime,
        ):

            timestamp = value

        # ---------------------------------------------------------------
        # ISO string
        # ---------------------------------------------------------------

        elif isinstance(
            value,
            str,
        ):

            try:
                timestamp = datetime.fromisoformat(
                    value.replace(
                        "Z",
                        "+00:00",
                    )
                )
            except ValueError:
                return None

        else:
            return None

        # ---------------------------------------------------------------
        # Normalize timezone
        # ---------------------------------------------------------------

        if timestamp.tzinfo is None:

            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        else:

            timestamp = timestamp.astimezone(
                timezone.utc
            )

        return timestamp

    # ------------------------------------------------------------------------

    @staticmethod
    def _is_private_or_loopback_ip(
        ip_address: str,
    ) -> bool:
        """
        Determine whether an IP is private/loopback.

        Uses the project's existing security helper when available.
        """

        if not ip_address:
            return True

        try:

            from app.core.security import (
                is_rfc1918_private_ip,
            )

            if is_rfc1918_private_ip(
                ip_address
            ):
                return True

        except (
            ImportError,
            AttributeError,
            ValueError,
        ):
            pass

        # Conservative loopback handling.
        if ip_address.startswith(
            "127."
        ):
            return True

        if ip_address == "::1":
            return True

        return False

    # =========================================================================
    # MAIN DETECTOR
    # =========================================================================

    @staticmethod
    def detect_anomalies(
        events: List[Any],
    ) -> AnomalyResult:
        """
        Analyze network telemetry events against deterministic
        home-network baselines.

        Accepts:

            - NetworkEvent ORM instances
            - Pydantic schema objects
            - dictionaries
        """

        # ====================================================================
        # BASIC INPUT NORMALIZATION
        # ====================================================================

        if not events:

            return AnomalyResult(
                anomaly_score=0.0,
                status=BaselineStatus.INSUFFICIENT_DATA,
                anomalies_detected=[],
                events_analyzed=0,
                baseline=AnomalyBaseline(
                    event_count=0,
                    status=BaselineStatus.INSUFFICIENT_DATA,
                    reasons=[
                        "Insufficient telemetry events "
                        "(<5 events) to compute baseline."
                    ],
                ),
            )

        event_count = len(events)

        # ====================================================================
        # BASELINE REQUIREMENT
        # ====================================================================

        if event_count < MIN_EVENTS_FOR_BASELINE:

            return AnomalyResult(
                anomaly_score=0.0,
                status=BaselineStatus.INSUFFICIENT_DATA,
                anomalies_detected=[],
                events_analyzed=event_count,
                baseline=AnomalyBaseline(
                    event_count=event_count,
                    status=BaselineStatus.INSUFFICIENT_DATA,
                    reasons=[
                        "Insufficient telemetry events "
                        f"(<{MIN_EVENTS_FOR_BASELINE} events) "
                        "to compute baseline."
                    ],
                ),
            )

        # ====================================================================
        # COLLECTIONS
        # ====================================================================

        anomalies: List[
            Dict[str, Any]
        ] = []

        score_accum = 0.0

        destination_ips: List[str] = []

        destination_ports: List[int] = []

        protocols: List[str] = []

        timestamps: List[datetime] = []

        explicit_anomalies_count = 0

        # ====================================================================
        # NORMALIZE EVENTS
        # ====================================================================

        for event in events:

            # ----------------------------------------------------------------
            # Destination IP
            # ----------------------------------------------------------------

            destination_ip = (
                self_value := BaselineAnomalyDetector._get_value(
                    event,
                    "destination_ip",
                    "",
                )
            )

            if destination_ip:

                destination_ips.append(
                    str(
                        destination_ip
                    )
                )

            # ----------------------------------------------------------------
            # Destination port
            # ----------------------------------------------------------------

            destination_port = (
                BaselineAnomalyDetector._get_value(
                    event,
                    "destination_port",
                    None,
                )
            )

            normalized_port = (
                BaselineAnomalyDetector._normalize_port(
                    destination_port
                )
            )

            if normalized_port is not None:

                destination_ports.append(
                    normalized_port
                )

            # ----------------------------------------------------------------
            # Protocol
            # ----------------------------------------------------------------

            protocol = (
                BaselineAnomalyDetector._normalize_protocol(
                    BaselineAnomalyDetector._get_value(
                        event,
                        "protocol",
                        "TCP",
                    )
                )
            )

            protocols.append(
                protocol
            )

            # ----------------------------------------------------------------
            # Timestamp
            # ----------------------------------------------------------------

            timestamp = (
                BaselineAnomalyDetector._normalize_timestamp(
                    BaselineAnomalyDetector._get_value(
                        event,
                        "event_timestamp",
                        None,
                    )
                )
            )

            if timestamp is not None:

                timestamps.append(
                    timestamp
                )

            # ----------------------------------------------------------------
            # Explicit anomaly flag
            # ----------------------------------------------------------------

            is_anomaly = (
                BaselineAnomalyDetector._get_value(
                    event,
                    "is_anomaly",
                    False,
                )
            )

            if bool(is_anomaly):

                explicit_anomalies_count += 1

        # ====================================================================
        # 1. EXPLICIT ANOMALY FLAGS
        # ====================================================================

        if explicit_anomalies_count > 0:

            anomaly_ratio = (
                explicit_anomalies_count
                / event_count
            )

            added_score = min(
                40.0,
                anomaly_ratio * 50.0,
            )

            score_accum += added_score

            anomalies.append(
                {
                    "type": "explicit_anomaly_flag",
                    "count": explicit_anomalies_count,
                    "reason": (
                        f"{explicit_anomalies_count} "
                        "events explicitly marked "
                        "as anomalous."
                    ),
                    "weight": round(
                        added_score,
                        2,
                    ),
                }
            )

        # ====================================================================
        # 2. REPEATED EXTERNAL DESTINATION
        # ====================================================================

        if destination_ips:

            ip_counts = Counter(
                destination_ips
            )

            most_common_ip, most_common_count = (
                ip_counts.most_common(1)[0]
            )

            concentration = (
                most_common_count
                / len(destination_ips)
            )

            is_private = (
                BaselineAnomalyDetector
                ._is_private_or_loopback_ip(
                    most_common_ip
                )
            )

            if (
                concentration >= 0.80
                and len(destination_ips) >= 8
                and not is_private
            ):

                score_accum += 25.0

                anomalies.append(
                    {
                        "type": "repeated_destination",
                        "destination_ip": (
                            most_common_ip
                        ),
                        "frequency_ratio": round(
                            concentration,
                            2,
                        ),
                        "reason": (
                            "High concentration of "
                            "traffic to external single "
                            f"IP {most_common_ip} "
                            f"({most_common_count}/"
                            f"{len(destination_ips)} "
                            "events)."
                        ),
                        "weight": 25.0,
                    }
                )

        # ====================================================================
        # 3. UNUSUAL PORT DISTRIBUTION
        # ====================================================================

        unusual_ports = [
            port
            for port in destination_ports
            if port not in STANDARD_HOME_PORTS
        ]

        if unusual_ports:

            unique_unusual_ports = set(
                unusual_ports
            )

            # ---------------------------------------------------------------
            # Potential port sweep
            # ---------------------------------------------------------------

            if len(unique_unusual_ports) >= 5:

                score_accum += 35.0

                anomalies.append(
                    {
                        "type": "port_sweep_indicator",
                        "ports": sorted(
                            unique_unusual_ports
                        ),
                        "reason": (
                            "Observed traffic targeting "
                            f"{len(unique_unusual_ports)} "
                            "non-standard ports, "
                            "indicating potential "
                            "port scanning."
                        ),
                        "weight": 35.0,
                    }
                )

            # ---------------------------------------------------------------
            # Majority unusual
            # ---------------------------------------------------------------

            elif (
                len(unusual_ports)
                / len(destination_ports)
                >= 0.5
            ):

                score_accum += 20.0

                anomalies.append(
                    {
                        "type": "unusual_ports",
                        "ports": sorted(
                            unique_unusual_ports
                        ),
                        "reason": (
                            "Majority of telemetry "
                            f"({len(unusual_ports)}/"
                            f"{len(destination_ports)}) "
                            "targets non-standard "
                            "home ports."
                        ),
                        "weight": 20.0,
                    }
                )

        # ====================================================================
        # 4. EVENT RATE / BURST ANALYSIS
        # ====================================================================

        timestamps_sorted = sorted(
            timestamps
        )

        average_rate_per_min = 0.0

        current_rate_per_min = 0.0

        deviation = 0.0

        if len(timestamps_sorted) >= 2:

            total_delta_seconds = max(
                (
                    timestamps_sorted[-1]
                    - timestamps_sorted[0]
                ).total_seconds(),
                1.0,
            )

            average_rate_per_min = (
                len(timestamps_sorted)
                / total_delta_seconds
            ) * 60.0

            recent_count = min(
                len(timestamps_sorted),
                5,
            )

            recent_start_index = (
                len(timestamps_sorted)
                - recent_count
            )

            recent_delta_seconds = max(
                (
                    timestamps_sorted[-1]
                    - timestamps_sorted[
                        recent_start_index
                    ]
                ).total_seconds(),
                1.0,
            )

            current_rate_per_min = (
                recent_count
                / recent_delta_seconds
            ) * 60.0

            if average_rate_per_min > 0:

                deviation = (
                    current_rate_per_min
                    / average_rate_per_min
                )

            if (
                current_rate_per_min > 60.0
                or deviation >= 3.0
            ):

                score_accum += 25.0

                anomalies.append(
                    {
                        "type": "elevated_event_rate",
                        "current_rate_per_min": round(
                            current_rate_per_min,
                            2,
                        ),
                        "deviation_factor": round(
                            deviation,
                            2,
                        ),
                        "reason": (
                            "Sudden event burst "
                            f"({round(current_rate_per_min, 1)} "
                            "events/min, "
                            f"{round(deviation, 1)}x "
                            "baseline)."
                        ),
                        "weight": 25.0,
                    }
                )

        # ====================================================================
        # 5. PROTOCOL DEVIATION
        # ====================================================================

        if protocols:

            protocol_counts = Counter(
                protocols
            )

            uncommon_count = sum(
                protocol_counts.get(
                    protocol,
                    0,
                )
                for protocol in UNCOMMON_PROTOCOLS
            )

            if uncommon_count > 0:

                observed_uncommon = sorted(
                    protocol
                    for protocol in UNCOMMON_PROTOCOLS
                    if protocol in protocol_counts
                )

                score_accum += 15.0

                anomalies.append(
                    {
                        "type": "protocol_deviation",
                        "protocols": observed_uncommon,
                        "count": uncommon_count,
                        "reason": (
                            f"Observed {uncommon_count} "
                            "events using uncommon "
                            "network protocols: "
                            f"{', '.join(observed_uncommon)}."
                        ),
                        "weight": 15.0,
                    }
                )

        # ====================================================================
        # FINAL SCORE
        # ====================================================================

        final_score = min(
            100.0,
            max(
                0.0,
                score_accum,
            ),
        )

        # ====================================================================
        # STATUS
        # ====================================================================

        if final_score <= 20.0:

            status = BaselineStatus.NORMAL

        elif final_score <= 50.0:

            status = BaselineStatus.ELEVATED

        elif final_score <= 80.0:

            status = BaselineStatus.ANOMALOUS

        else:

            status = BaselineStatus.SEVERE_ANOMALY

        # ====================================================================
        # BASELINE SUMMARY
        # ====================================================================

        baseline_reasons = (
            [
                anomaly["reason"]
                for anomaly in anomalies
            ]
            if anomalies
            else [
                "Telemetry conforms to baseline expectations."
            ]
        )

        baseline_summary = AnomalyBaseline(
            baseline_window_seconds=3600.0,
            event_count=event_count,
            known_destination_ports=sorted(
                set(destination_ports)
            )[:15],
            known_protocols=sorted(
                set(protocols)
            ),
            average_event_rate=round(
                average_rate_per_min,
                2,
            ),
            current_event_rate=round(
                current_rate_per_min,
                2,
            ),
            deviation=round(
                deviation,
                2,
            ),
            status=status,
            reasons=baseline_reasons,
        )

        # ====================================================================
        # FINAL RESULT
        # ====================================================================

        return AnomalyResult(
            anomaly_score=round(
                final_score,
                2,
            ),
            status=status,
            anomalies_detected=anomalies,
            events_analyzed=event_count,
            baseline=baseline_summary,
        )