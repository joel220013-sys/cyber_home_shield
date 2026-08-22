"""
Deterministic exposure analysis for observed device ports and services.

This module is responsible only for calculating network exposure.

Risk classification rules are centralized in:
    app.services.risk_engine.risk_rules

This keeps ExposureAnalyzer and FindingAggregator synchronized.
"""

from typing import Any, Dict, List

from app.services.risk_engine.models import ExposureResult
from app.services.risk_engine.risk_rules import (
    DEFAULT_UNKNOWN_PORT_WEIGHT,
    DETERMINISTIC_RISKY_PORTS,
    PORT_EXPOSURE_WEIGHTS,
    RISKY_WEIGHT_THRESHOLD,
    get_port_description,
)


class ExposureAnalyzer:
    """
    Evaluate network service exposure from observed ports.

    Policy:

    1. Exposure score always comes from deterministic port weights.
    2. Deterministic security-relevant ports always count as risky.
    3. For other ports:
       - explicit persisted `is_risky` is respected
       - otherwise the deterministic weight threshold is used.
    4. Duplicate ports are counted only once.
    5. Invalid ports are ignored.
    """

    # ========================================================================
    # NORMALIZE RISK FLAG
    # ========================================================================

    @staticmethod
    def _normalize_risk_flag(
        value: Any,
    ) -> bool | None:
        """
        Normalize an `is_risky` value.

        Returns:

            True
                Explicitly risky.

            False
                Explicitly not risky.

            None
                Value unavailable or unsupported.

        Supported values:

            bool
            int
            float
            "true"
            "false"
            "1"
            "0"
            "yes"
            "no"
            "y"
            "n"
            "on"
            "off"
        """

        if value is None:
            return None

        # --------------------------------------------------------------------
        # Boolean
        # --------------------------------------------------------------------

        if isinstance(value, bool):
            return value

        # --------------------------------------------------------------------
        # Numeric
        # --------------------------------------------------------------------

        if isinstance(value, (int, float)):
            return bool(value)

        # --------------------------------------------------------------------
        # String
        # --------------------------------------------------------------------

        if isinstance(value, str):

            normalized = value.strip().lower()

            if normalized in {
                "true",
                "1",
                "yes",
                "y",
                "on",
            }:
                return True

            if normalized in {
                "false",
                "0",
                "no",
                "n",
                "off",
            }:
                return False

        # --------------------------------------------------------------------
        # Unknown representation
        # --------------------------------------------------------------------

        return None

    # ========================================================================
    # EXTRACT PORT
    # ========================================================================

    @staticmethod
    def _extract_port(
        item: Any,
    ) -> int | None:
        """
        Extract and validate a port number.

        Supported input:

            - integer
            - ORM object
            - Pydantic schema
            - dictionary
        """

        port = None

        # --------------------------------------------------------------------
        # Integer input
        # --------------------------------------------------------------------

        if isinstance(item, int):
            port = item

        # --------------------------------------------------------------------
        # ORM / schema object
        # --------------------------------------------------------------------

        elif hasattr(item, "port_number"):

            port = getattr(
                item,
                "port_number",
                None,
            )

        # --------------------------------------------------------------------
        # Dictionary
        # --------------------------------------------------------------------

        elif isinstance(item, dict):

            port = item.get(
                "port_number"
            )

        # --------------------------------------------------------------------
        # Missing
        # --------------------------------------------------------------------

        if port is None:
            return None

        # --------------------------------------------------------------------
        # Convert to integer
        # --------------------------------------------------------------------

        try:

            port = int(port)

        except (
            TypeError,
            ValueError,
        ):

            return None

        # --------------------------------------------------------------------
        # Validate port range
        # --------------------------------------------------------------------

        if not 1 <= port <= 65535:
            return None

        return port

    # ========================================================================
    # EXTRACT EXPLICIT RISK
    # ========================================================================

    @staticmethod
    def _extract_explicit_risk(
        item: Any,
    ) -> bool | None:
        """
        Extract persisted `is_risky` metadata.

        Returns None when no explicit metadata exists.
        """

        # --------------------------------------------------------------------
        # ORM / schema object
        # --------------------------------------------------------------------

        if hasattr(
            item,
            "is_risky",
        ):

            return ExposureAnalyzer._normalize_risk_flag(
                getattr(
                    item,
                    "is_risky",
                    None,
                )
            )

        # --------------------------------------------------------------------
        # Dictionary
        # --------------------------------------------------------------------

        if (
            isinstance(item, dict)
            and "is_risky" in item
        ):

            return ExposureAnalyzer._normalize_risk_flag(
                item.get(
                    "is_risky"
                )
            )

        return None

    # ========================================================================
    # GET EXPOSURE WEIGHT
    # ========================================================================

    @staticmethod
    def _get_exposure_weight(
        port: int,
    ) -> float:
        """
        Return deterministic exposure weight for a port.

        Unknown ports receive DEFAULT_UNKNOWN_PORT_WEIGHT.
        """

        return PORT_EXPOSURE_WEIGHTS.get(
            port,
            DEFAULT_UNKNOWN_PORT_WEIGHT,
        )

    # ========================================================================
    # DETERMINE RISK
    # ========================================================================

    @staticmethod
    def _determine_risk(
        port: int,
        explicit_risk: bool | None,
        weight: float,
    ) -> tuple[bool, str]:
        """
        Determine whether a port is security-relevant.

        Priority:

            1. Deterministic risky-port rule
            2. Explicit persisted metadata
            3. Deterministic weight threshold
        """

        # --------------------------------------------------------------------
        # Deterministic risky ports ALWAYS win.
        #
        # Example:
        #
        # Database:
        #     port = 80
        #     is_risky = False
        #
        # Deterministic rule:
        #     port 80 = risky
        #
        # Final:
        #     risky = True
        # --------------------------------------------------------------------

        if port in DETERMINISTIC_RISKY_PORTS:

            return (
                True,
                "deterministic_port_rule",
            )

        # --------------------------------------------------------------------
        # Explicit persisted risk
        # --------------------------------------------------------------------

        if explicit_risk is not None:

            return (
                explicit_risk,
                "persisted",
            )

        # --------------------------------------------------------------------
        # Deterministic weight fallback
        # --------------------------------------------------------------------

        is_risky = (
            weight >= RISKY_WEIGHT_THRESHOLD
        )

        return (
            is_risky,
            "deterministic_weight",
        )

    # ========================================================================
    # ANALYZE PORTS
    # ========================================================================

    @staticmethod
    def analyze_ports(
        open_ports: List[Any],
    ) -> ExposureResult:
        """
        Calculate deterministic network exposure.

        Supported inputs:

            - OpenPort ORM objects
            - OpenPort Pydantic schemas
            - dictionaries
            - integer port numbers

        Exposure score:

            Sum of deterministic port exposure weights.

        Risk classification:

            Deterministic risky ports always remain risky.

            For other ports, explicit persisted `is_risky`
            metadata is respected.

            If metadata is unavailable, the exposure-weight
            threshold is used.
        """

        # ====================================================================
        # EMPTY INPUT
        # ====================================================================

        if not open_ports:

            return ExposureResult(
                exposure_score=0.0,
                open_ports_count=0,
                risky_services_count=0,
                service_exposures=[],
                reasons=[
                    "No open services observed."
                ],
            )

        # ====================================================================
        # CALCULATION STATE
        # ====================================================================

        total_weight = 0.0

        service_exposures: List[
            Dict[str, Any]
        ] = []

        reasons: List[str] = []

        risky_count = 0

        unique_ports: set[int] = set()

        # ====================================================================
        # PROCESS OBSERVED PORTS
        # ====================================================================

        for item in open_ports:

            # ----------------------------------------------------------------
            # Extract port
            # ----------------------------------------------------------------

            port = ExposureAnalyzer._extract_port(
                item
            )

            if port is None:
                continue

            # ----------------------------------------------------------------
            # Deduplicate
            # ----------------------------------------------------------------

            if port in unique_ports:
                continue

            unique_ports.add(port)

            # ----------------------------------------------------------------
            # Calculate deterministic exposure weight
            # ----------------------------------------------------------------

            weight = ExposureAnalyzer._get_exposure_weight(
                port
            )

            # ----------------------------------------------------------------
            # Extract persisted risk metadata
            # ----------------------------------------------------------------

            explicit_risk = (
                ExposureAnalyzer._extract_explicit_risk(
                    item
                )
            )

            # ----------------------------------------------------------------
            # Determine risk
            # ----------------------------------------------------------------

            is_risky, risk_source = (
                ExposureAnalyzer._determine_risk(
                    port=port,
                    explicit_risk=explicit_risk,
                    weight=weight,
                )
            )

            # ----------------------------------------------------------------
            # Risky count
            # ----------------------------------------------------------------

            if is_risky:
                risky_count += 1

            # ----------------------------------------------------------------
            # Human-readable description
            # ----------------------------------------------------------------

            description = get_port_description(
                port
            )

            # ----------------------------------------------------------------
            # Service information
            # ----------------------------------------------------------------

            service_info = {
                "port": port,
                "weight": weight,
                "is_risky": is_risky,
                "risk_source": risk_source,
                "description": description,
            }

            service_exposures.append(
                service_info
            )

            # ----------------------------------------------------------------
            # Human-readable reason
            # ----------------------------------------------------------------

            reasons.append(
                f"Port {port}: "
                f"{description} "
                f"(weight: {weight}, "
                f"risky: {is_risky}, "
                f"source: {risk_source})"
            )

            # ----------------------------------------------------------------
            # Add exposure contribution
            # ----------------------------------------------------------------

            total_weight += weight

        # ====================================================================
        # NO VALID PORTS
        # ====================================================================

        if not unique_ports:

            return ExposureResult(
                exposure_score=0.0,
                open_ports_count=0,
                risky_services_count=0,
                service_exposures=[],
                reasons=[
                    "No valid open ports observed."
                ],
            )

        # ====================================================================
        # CLAMP EXPOSURE SCORE
        # ====================================================================

        clamped_score = min(
            100.0,
            max(
                0.0,
                total_weight,
            ),
        )

        # ====================================================================
        # RETURN RESULT
        # ====================================================================

        return ExposureResult(
            exposure_score=round(
                clamped_score,
                2,
            ),
            open_ports_count=len(
                unique_ports
            ),
            risky_services_count=risky_count,
            service_exposures=service_exposures,
            reasons=reasons,
        )