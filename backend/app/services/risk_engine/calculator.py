"""Deterministic Cyber Home Shield Risk Score Calculator."""

import uuid
from typing import Any, Dict, List, Optional

from app.models.enums import FindingStatus, Severity

from app.services.risk_engine.anomaly_detector import (
    BaselineAnomalyDetector,
)

from app.services.risk_engine.exposure import (
    ExposureAnalyzer,
)

from app.services.risk_engine.models import (
    AnomalyResult,
    DeviceRiskResult,
    EvaluatedFinding,
    ExposureResult,
    NetworkPostureResult,
    VulnerabilityResult,
)
from app.services.risk_engine.finding_aggregator import FindingAggregator


# ============================================================================
# CONFIGURATION
# ============================================================================

EXPOSURE_WEIGHT = 0.40
VULNERABILITY_WEIGHT = 0.40
ANOMALY_WEIGHT = 0.20


# ============================================================================
# NORMALIZED FINDING SEVERITY SCORES
# ============================================================================

SEVERITY_VALUES: Dict[Severity, float] = {
    Severity.INFO: 5.0,
    Severity.LOW: 20.0,
    Severity.MEDIUM: 45.0,
    Severity.HIGH: 70.0,
    Severity.CRITICAL: 95.0,
}


# ============================================================================
# ACTIVE FINDING STATUSES
# ============================================================================

ACTIVE_FINDING_STATUSES = {
    FindingStatus.OPEN,
    FindingStatus.IN_PROGRESS,
}


class RiskCalculator:
    """Compute deterministic and explainable device/network risk scores.

    Overall formula:

        overall_score =
            (exposure_score * 0.40)
            + (vulnerability_score * 0.40)
            + (anomaly_score * 0.20)

    IMPORTANT:

        This class calculates risk from supplied data.

        It does NOT create or persist SecurityFinding records.

        SecurityFinding generation/persistence must be performed by
        the discovery/service/API layer.
    """

    # ========================================================================
    # FINDING HELPERS
    # ========================================================================

    @staticmethod
    def _get_value(
        finding: Any,
        field: str,
        default: Any = None,
    ) -> Any:
        """Read a field from either an ORM object or dictionary."""

        if isinstance(finding, dict):
            return finding.get(field, default)

        return getattr(
            finding,
            field,
            default,
        )

    @staticmethod
    def _normalize_finding_status(
        finding: Any,
    ) -> Optional[FindingStatus]:
        """Normalize finding status to FindingStatus."""

        raw_status = RiskCalculator._get_value(
            finding,
            "status",
            None,
        )

        if isinstance(
            raw_status,
            FindingStatus,
        ):
            return raw_status

        if raw_status is None:
            return None

        try:
            return FindingStatus(
                str(raw_status).upper()
            )
        except (
            ValueError,
            TypeError,
        ):
            return None

    @staticmethod
    def _normalize_severity(
        finding: Any,
    ) -> Optional[Severity]:
        """Normalize finding severity to Severity."""

        raw_severity = RiskCalculator._get_value(
            finding,
            "severity",
            None,
        )

        if isinstance(
            raw_severity,
            Severity,
        ):
            return raw_severity

        if raw_severity is None:
            return None

        try:
            return Severity(
                str(raw_severity).upper()
            )
        except (
            ValueError,
            TypeError,
        ):
            return None

    @staticmethod
    def _is_active_finding(
        finding: Any,
    ) -> bool:
        """Return True only for OPEN or IN_PROGRESS findings."""

        status_value = (
            RiskCalculator._normalize_finding_status(
                finding
            )
        )

        return status_value in ACTIVE_FINDING_STATUSES

    @staticmethod
    def _finding_identity(finding: Any) -> tuple:
        """Identify a finding consistently across generated and persisted data."""
        evidence = RiskCalculator._get_value(finding, "evidence", {}) or {}
        if not isinstance(evidence, dict):
            evidence = {}

        if evidence.get("source") == "open_port":
            return (
                RiskCalculator._get_value(finding, "category", ""),
                RiskCalculator._get_value(finding, "title", ""),
                evidence.get("port"),
                evidence.get("protocol"),
            )

        return (
            RiskCalculator._get_value(finding, "category", ""),
            RiskCalculator._get_value(finding, "title", ""),
        )

    # ========================================================================
    # VULNERABILITY SUBSCORE
    # ========================================================================

    @staticmethod
    def calculate_vulnerability_subscore(
        findings: List[Any],
    ) -> VulnerabilityResult:
        """Calculate vulnerability score from active vulnerability findings.

        Scoring:

            Highest severity = base score

            Additional vulnerability findings =
                15% of their normalized severity

            ANOMALY findings are excluded because anomaly findings
            are already represented by the separate anomaly subscore.

            Final score is capped at 100.
        """

        # ====================================================================
        # 1. Filter active findings
        # ====================================================================

        active_findings: List[Any] = [
            finding
            for finding in findings
            if RiskCalculator._is_active_finding(
                finding
            )
        ]

        # ====================================================================
        # 2. No active findings
        # ====================================================================

        if not active_findings:
            return VulnerabilityResult(
                vulnerability_score=0.0,
                findings_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                reasons=[
                    "No active security findings identified."
                ],
            )

        # ====================================================================
        # 3. Initialize scoring
        # ====================================================================

        severity_scores: List[float] = []

        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }

        reasons: List[str] = []

        skipped_anomaly_count = 0

        # ====================================================================
        # 4. Process findings
        # ====================================================================

        for finding in active_findings:

            # ----------------------------------------------------------------
            # Category
            #
            # We intentionally DO NOT import FindingCategory because your
            # project does not define that enum.
            # ----------------------------------------------------------------

            category = RiskCalculator._get_value(
                finding,
                "category",
                None,
            )

            category_value = ""

            if category is not None:
                category_value = str(
                    category
                ).upper().strip()

            # ----------------------------------------------------------------
            # Exclude ANOMALY findings from vulnerability scoring
            # ----------------------------------------------------------------

            if category_value == "ANOMALY":
                skipped_anomaly_count += 1
                continue

            # ----------------------------------------------------------------
            # Normalize severity
            # ----------------------------------------------------------------

            severity = (
                RiskCalculator._normalize_severity(
                    finding
                )
            )

            # ----------------------------------------------------------------
            # Ignore invalid severity
            # ----------------------------------------------------------------

            if severity not in SEVERITY_VALUES:
                continue

            # ----------------------------------------------------------------
            # Count severity
            # ----------------------------------------------------------------

            counts[severity] += 1

            # ----------------------------------------------------------------
            # Convert severity to score
            # ----------------------------------------------------------------

            value = SEVERITY_VALUES[
                severity
            ]

            severity_scores.append(
                value
            )

            # ----------------------------------------------------------------
            # Finding title
            # ----------------------------------------------------------------

            title = (
                RiskCalculator._get_value(
                    finding,
                    "title",
                    "Finding",
                )
                or "Finding"
            )

            # ----------------------------------------------------------------
            # Explainable reason
            # ----------------------------------------------------------------

            reasons.append(
                f"[{severity.value}] "
                f"{title} "
                f"(score: {value})"
            )

        # ====================================================================
        # 5. Add explanation when anomaly findings were excluded
        # ====================================================================

        if skipped_anomaly_count > 0:
            reasons.append(
                f"Excluded {skipped_anomaly_count} "
                f"ANOMALY finding(s) from vulnerability "
                f"scoring because anomaly risk is calculated "
                f"separately."
            )

        # ====================================================================
        # 6. No valid vulnerability findings
        # ====================================================================

        if not severity_scores:
            return VulnerabilityResult(
                vulnerability_score=0.0,
                findings_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                info_count=0,
                reasons=(
                    reasons
                    if reasons
                    else [
                        "No evaluable active vulnerability findings found."
                    ]
                ),
            )

        # ====================================================================
        # 7. Highest severity first
        # ====================================================================

        severity_scores.sort(
            reverse=True
        )

        # ====================================================================
        # 8. Highest severity = base score
        # ====================================================================

        base_score = severity_scores[0]

        # ====================================================================
        # 9. Additional findings contribute 15%
        # ====================================================================

        secondary_contribution = (
            sum(
                severity_scores[1:]
            )
            * 0.15
        )

        # ====================================================================
        # 10. Final vulnerability score
        # ====================================================================

        final_vulnerability_score = min(
            100.0,
            base_score
            + secondary_contribution,
        )

        # ====================================================================
        # 11. Return result
        # ====================================================================

        return VulnerabilityResult(
            vulnerability_score=round(
                final_vulnerability_score,
                2,
            ),
            findings_count=len(
                severity_scores
            ),
            critical_count=counts[
                Severity.CRITICAL
            ],
            high_count=counts[
                Severity.HIGH
            ],
            medium_count=counts[
                Severity.MEDIUM
            ],
            low_count=counts[
                Severity.LOW
            ],
            info_count=counts[
                Severity.INFO
            ],
            reasons=reasons,
        )

    # ========================================================================
    # DEVICE RISK
    # ========================================================================

    @classmethod
    def calculate_device_risk(
        cls,
        device_id: uuid.UUID,
        open_ports: Optional[List[Any]] = None,
        events: Optional[List[Any]] = None,
        existing_findings: Optional[List[Any]] = None,
    ) -> DeviceRiskResult:
        """Calculate complete deterministic device risk.

        Findings are supplied from the persistence layer.

        This method does NOT create or persist findings.
        """

        # ====================================================================
        # Normalize input
        # ====================================================================

        open_ports = (
            open_ports
            if open_ports is not None
            else []
        )

        events = (
            events
            if events is not None
            else []
        )

        existing_findings = (
            existing_findings
            if existing_findings is not None
            else []
        )

        # ====================================================================
        # 1. Exposure
        # ====================================================================

        exposure_result: ExposureResult = (
            ExposureAnalyzer.analyze_ports(
                open_ports
            )
        )

        # ====================================================================
        # 2. Anomaly
        # ====================================================================

        anomaly_result: AnomalyResult = (
            BaselineAnomalyDetector.detect_anomalies(
                events
            )
        )

        # ====================================================================
        # 3. Current port findings plus persisted findings
        # ====================================================================

        generated_findings = FindingAggregator.generate_findings_from_ports(
            device_id,
            open_ports,
        )
        all_findings_by_identity = {
            cls._finding_identity(finding): finding
            for finding in existing_findings
        }
        for finding in generated_findings:
            all_findings_by_identity.setdefault(
                cls._finding_identity(finding),
                finding,
            )
        all_findings = list(all_findings_by_identity.values())

        # ====================================================================
        # 4. Vulnerability
        # ====================================================================

        vulnerability_result: VulnerabilityResult = (
            cls.calculate_vulnerability_subscore(
                all_findings
            )
        )

        # ====================================================================
        # 5. Weighted risk calculation
        # ====================================================================

        exposure_contribution = (
            exposure_result.exposure_score
            * EXPOSURE_WEIGHT
        )

        vulnerability_contribution = (
            vulnerability_result.vulnerability_score
            * VULNERABILITY_WEIGHT
        )

        anomaly_contribution = (
            anomaly_result.anomaly_score
            * ANOMALY_WEIGHT
        )

        overall_score = min(
            100.0,
            max(
                0.0,
                exposure_contribution
                + vulnerability_contribution
                + anomaly_contribution,
            ),
        )

        # ====================================================================
        # 6. Score breakdown
        # ====================================================================

        score_breakdown = {
            "exposure": {
                "weight": EXPOSURE_WEIGHT,
                "score": (
                    exposure_result.exposure_score
                ),
                "weighted_contribution": round(
                    exposure_contribution,
                    2,
                ),
            },
            "vulnerability": {
                "weight": VULNERABILITY_WEIGHT,
                "score": (
                    vulnerability_result.vulnerability_score
                ),
                "weighted_contribution": round(
                    vulnerability_contribution,
                    2,
                ),
            },
            "anomaly": {
                "weight": ANOMALY_WEIGHT,
                "score": (
                    anomaly_result.anomaly_score
                ),
                "weighted_contribution": round(
                    anomaly_contribution,
                    2,
                ),
            },
        }

        # ====================================================================
        # 7. Summary
        # ====================================================================

        summary_notes = (
            f"Risk Score: "
            f"{round(overall_score, 1)}/100 | "
            f"Exposure: "
            f"{round(exposure_result.exposure_score, 1)} "
            f"({len(open_ports)} ports) | "
            f"Active Findings: "
            f"{vulnerability_result.findings_count} "
            f"("
            f"{vulnerability_result.critical_count} crit, "
            f"{vulnerability_result.high_count} high, "
            f"{vulnerability_result.medium_count} medium, "
            f"{vulnerability_result.low_count} low"
            f") | "
            f"Anomaly Status: "
            f"{anomaly_result.status.value}"
        )

        # ====================================================================
        # 8. Convert persisted findings to API models
        # ====================================================================

        final_findings_list: List[
            EvaluatedFinding
        ] = []

        for finding in all_findings:

            # ----------------------------------------------------------------
            # Already converted
            # ----------------------------------------------------------------

            if isinstance(
                finding,
                EvaluatedFinding,
            ):
                final_findings_list.append(
                    finding
                )
                continue

            # ----------------------------------------------------------------
            # Extract common fields
            # ----------------------------------------------------------------

            finding_id = (
                RiskCalculator._get_value(
                    finding,
                    "id",
                    None,
                )
            )

            title = (
                RiskCalculator._get_value(
                    finding,
                    "title",
                    "Finding",
                )
                or "Finding"
            )

            category = (
                RiskCalculator._get_value(
                    finding,
                    "category",
                    "General",
                )
                or "General"
            )

            severity = (
                RiskCalculator._normalize_severity(
                    finding
                )
            )

            if severity is None:
                continue

            status_value = (
                RiskCalculator._normalize_finding_status(
                    finding
                )
            )

            if status_value is None:
                status_value = FindingStatus.OPEN

            description = (
                RiskCalculator._get_value(
                    finding,
                    "description",
                    "",
                )
                or ""
            )

            evidence = (
                RiskCalculator._get_value(
                    finding,
                    "evidence",
                    {},
                )
            )

            if evidence is None:
                evidence = {}

            if not isinstance(
                evidence,
                dict,
            ):
                try:
                    evidence = dict(
                        evidence
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    evidence = {}

            remediation_steps = (
                RiskCalculator._get_value(
                    finding,
                    "remediation_steps",
                    "",
                )
                or ""
            )

            cve_id = (
                RiskCalculator._get_value(
                    finding,
                    "cve_id",
                    "",
                )
                or ""
            )

            # ----------------------------------------------------------------
            # Build API finding
            # ----------------------------------------------------------------

            final_findings_list.append(
                EvaluatedFinding(
                    finding_id=finding_id,
                    device_id=device_id,
                    title=title,
                    category=category,
                    severity=severity,
                    status=status_value,
                    description=description,
                    evidence=evidence,
                    remediation_steps=remediation_steps,
                    cve_id=cve_id,
                )
            )

        # ====================================================================
        # 9. Return device risk
        # ====================================================================

        return DeviceRiskResult(
            device_id=device_id,
            overall_score=round(
                overall_score,
                2,
            ),
            exposure_subscore=round(
                exposure_result.exposure_score,
                2,
            ),
            vulnerability_subscore=round(
                vulnerability_result.vulnerability_score,
                2,
            ),
            anomaly_subscore=round(
                anomaly_result.anomaly_score,
                2,
            ),
            critical_findings_count=(
                vulnerability_result.critical_count
            ),
            high_findings_count=(
                vulnerability_result.high_count
            ),
            open_risky_ports_count=(
                exposure_result.risky_services_count
            ),
            score_breakdown=score_breakdown,
            summary_notes=summary_notes[:500],
            findings=final_findings_list,
        )

    # ========================================================================
    # NETWORK POSTURE
    # ========================================================================

    @classmethod
    def calculate_network_posture(
        cls,
        device_results: List[
            DeviceRiskResult
        ],
    ) -> NetworkPostureResult:
        """Aggregate device risk into network posture.

        Formula:

            network_score =
                (average_device_score * 0.70)
                + (maximum_device_score * 0.30)
        """

        # ====================================================================
        # Empty network
        # ====================================================================

        if not device_results:
            return NetworkPostureResult(
                network_risk_score=0.0,
                total_devices=0,
                vulnerable_devices=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
                active_anomalies=0,
                device_scores={},
                posture_breakdown={
                    "status": "No devices analyzed",
                    "average_device_score": 0.0,
                    "max_device_score": 0.0,
                    "formula": (
                        "network_score = "
                        "(avg_score * 0.70) + "
                        "(max_score * 0.30)"
                    ),
                },
            )

        # ====================================================================
        # Aggregation variables
        # ====================================================================

        device_scores: Dict[
            str,
            float,
        ] = {}

        total_score = 0.0
        max_score = 0.0

        vulnerable_count = 0

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        active_anomalies = 0

        # ====================================================================
        # Process devices
        # ====================================================================

        for result in device_results:

            device_id_string = str(
                result.device_id
            )

            score = float(
                result.overall_score
            )

            device_scores[
                device_id_string
            ] = score

            total_score += score

            # ---------------------------------------------------------------
            # Maximum score
            # ---------------------------------------------------------------

            if score > max_score:
                max_score = score

            # ---------------------------------------------------------------
            # Vulnerable device
            # ---------------------------------------------------------------

            if (
                score >= 40.0
                or result.critical_findings_count > 0
                or result.high_findings_count > 0
            ):
                vulnerable_count += 1

            # ---------------------------------------------------------------
            # Critical / High counts
            # ---------------------------------------------------------------

            critical_count += (
                result.critical_findings_count
            )

            high_count += (
                result.high_findings_count
            )

            # ---------------------------------------------------------------
            # Active anomaly count
            # ---------------------------------------------------------------

            if (
                result.anomaly_subscore
                > 20.0
            ):
                active_anomalies += 1

            # ---------------------------------------------------------------
            # Medium / Low active findings
            # ---------------------------------------------------------------

            for finding in result.findings:

                finding_status = (
                    cls._normalize_finding_status(
                        finding
                    )
                )

                if (
                    finding_status
                    not in ACTIVE_FINDING_STATUSES
                ):
                    continue

                finding_severity = (
                    cls._normalize_severity(
                        finding
                    )
                )

                if (
                    finding_severity
                    == Severity.MEDIUM
                ):
                    medium_count += 1

                elif (
                    finding_severity
                    == Severity.LOW
                ):
                    low_count += 1

        # ====================================================================
        # Average score
        # ====================================================================

        average_score = (
            total_score
            / len(device_results)
        )

        # ====================================================================
        # Network risk score
        # ====================================================================

        network_risk_score = min(
            100.0,
            (
                average_score * 0.70
            )
            + (
                max_score * 0.30
            ),
        )

        # ====================================================================
        # Return network posture
        # ====================================================================

        return NetworkPostureResult(
            network_risk_score=round(
                network_risk_score,
                2,
            ),
            total_devices=len(
                device_results
            ),
            vulnerable_devices=(
                vulnerable_count
            ),
            critical_findings=(
                critical_count
            ),
            high_findings=(
                high_count
            ),
            medium_findings=(
                medium_count
            ),
            low_findings=(
                low_count
            ),
            active_anomalies=(
                active_anomalies
            ),
            device_scores=device_scores,
            posture_breakdown={
                "average_device_score": round(
                    average_score,
                    2,
                ),
                "max_device_score": round(
                    max_score,
                    2,
                ),
                "formula": (
                    "network_score = "
                    "(avg_score * 0.70) + "
                    "(max_score * 0.30)"
                ),
            },
        )