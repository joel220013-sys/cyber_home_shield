"""
Risk Assessment and Network Posture API Endpoints.

Provides deterministic defensive risk calculations, security finding
persistence, finding reconciliation, network posture aggregation,
evidence persistence, and resource ownership protection.
"""

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_db,
    get_optional_current_user,
)
from app.models.device import Device
from app.models.enums import FindingStatus
from app.models.risk_assessment import RiskAssessment
from app.models.security_finding import SecurityFinding
from app.models.user import User

from app.services.risk_engine.anomaly_detector import (
    BaselineAnomalyDetector,
)
from app.services.risk_engine.calculator import (
    RiskCalculator,
)
from app.services.risk_engine.finding_aggregator import (
    FindingAggregator,
)
from app.services.risk_engine.models import (
    DeviceRiskResult,
    EvaluatedFinding,
    FindingCategory,
    NetworkPostureResult,
)


router = APIRouter(
    prefix="/risk",
    tags=["Risk Engine"],
)


def _finding_identity(finding: Any) -> tuple:
    """Return a stable identity for a persisted or generated finding."""
    evidence = getattr(finding, "evidence", None) or {}
    if not isinstance(evidence, dict):
        evidence = {}

    if evidence.get("source") == "open_port":
        return (
            getattr(finding, "category", ""),
            getattr(finding, "title", ""),
            evidence.get("port"),
            evidence.get("protocol"),
        )

    return (
        getattr(finding, "category", ""),
        getattr(finding, "title", ""),
    )


# ============================================================================
# FINDING PERSISTENCE
# ============================================================================


async def _persist_generated_findings(
    db: AsyncSession,
    device: Device,
    generated_findings: List[EvaluatedFinding],
) -> List[SecurityFinding]:
    """
    Persist currently observed deterministic findings.

    Existing findings are matched using device-local category/title identity,
    plus port/protocol evidence for port findings.

    Currently observed findings are marked OPEN and their evidence
    is synchronized with the latest observation.
    """

    persisted_findings: List[SecurityFinding] = []

    existing_result = await db.execute(
        select(SecurityFinding).where(
            SecurityFinding.device_id == device.id,
        )
    )

    existing_by_key = {
        _finding_identity(existing): existing
        for existing in existing_result.scalars().all()
    }

    for finding in generated_findings:

        # ------------------------------------------------------------------
        # Normalize evidence
        # ------------------------------------------------------------------

        finding_evidence = getattr(
            finding,
            "evidence",
            {},
        )

        if finding_evidence is None:
            finding_evidence = {}

        if not isinstance(finding_evidence, dict):
            try:
                finding_evidence = dict(finding_evidence)
            except (TypeError, ValueError):
                finding_evidence = {}

        # ------------------------------------------------------------------
        # Find existing finding by the same identity keys used previously.
        # ------------------------------------------------------------------

        existing = existing_by_key.get(
            _finding_identity(finding)
        )

        # ------------------------------------------------------------------
        # Update existing finding
        # ------------------------------------------------------------------

        if existing:

            existing.severity = finding.severity
            existing.status = FindingStatus.OPEN
            existing.description = finding.description

            existing.remediation_steps = (
                finding.remediation_steps or ""
            )

            existing.cve_id = (
                getattr(
                    finding,
                    "cve_id",
                    "",
                )
                or ""
            )

            existing.evidence = finding_evidence

            persisted_findings.append(existing)

        # ------------------------------------------------------------------
        # Create new finding
        # ------------------------------------------------------------------

        else:

            new_finding = SecurityFinding(
                id=uuid.uuid4(),
                device_id=device.id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity,
                status=FindingStatus.OPEN,
                description=finding.description,
                remediation_steps=(
                    finding.remediation_steps or ""
                ),
                cve_id=(
                    getattr(
                        finding,
                        "cve_id",
                        "",
                    )
                    or ""
                ),
                evidence=finding_evidence,
            )

            device.findings.append(new_finding)
            db.add(new_finding)

            persisted_findings.append(new_finding)

    await db.flush()

    return persisted_findings


# ============================================================================
# GENERATE + PERSIST + RECONCILE FINDINGS
# ============================================================================


async def _generate_and_persist_findings(
    db: AsyncSession,
    device: Device,
) -> List[SecurityFinding]:
    """
    Generate findings from current device observations and reconcile
    previously persisted findings.

    Rules:

    1. Currently observed finding -> OPEN.
    2. Previously OPEN finding no longer observed -> RESOLVED.
    3. IN_PROGRESS finding no longer observed -> remains IN_PROGRESS.
    4. Only OPEN and IN_PROGRESS findings participate in risk scoring.
    5. Previously RESOLVED/IGNORED findings can be reopened when
       the current deterministic engine observes the same condition.
    """

    generated_findings: List[EvaluatedFinding] = []

    # ========================================================================
    # 1. Generate findings from current open ports
    # ========================================================================

    port_findings = (
        FindingAggregator.generate_findings_from_ports(
            device.id,
            device.ports,
        )
    )

    generated_findings.extend(port_findings)

    # ========================================================================
    # 2. Generate anomaly findings
    # ========================================================================

    anomaly_result = (
        BaselineAnomalyDetector.detect_anomalies(
            device.events
        )
    )

    anomaly_findings = (
        FindingAggregator.generate_findings_from_anomalies(
            device.id,
            anomaly_result,
        )
    )

    generated_findings.extend(anomaly_findings)

    # ========================================================================
    # 3. Persist current findings
    # ========================================================================

    await _persist_generated_findings(
        db=db,
        device=device,
        generated_findings=generated_findings,
    )

    # ========================================================================
    # 4. Build keys for current findings
    # ========================================================================

    current_keys = {
        _finding_identity(finding)
        for finding in generated_findings
    }

    # ========================================================================
    # 5. Load all persisted findings for this device
    # ========================================================================

    result = await db.execute(
        select(SecurityFinding).where(
            SecurityFinding.device_id == device.id
        )
    )

    existing_findings = result.scalars().all()

    # ========================================================================
    # 6. Resolve stale OPEN findings
    # ========================================================================

    for existing in existing_findings:

        existing_key = _finding_identity(existing)

        if (
            existing.status == FindingStatus.OPEN
            and existing.category != FindingCategory.ANOMALY.value
            and existing_key not in current_keys
        ):
            existing.status = FindingStatus.RESOLVED

    await db.flush()

    # ========================================================================
    # 7. Derive active findings from the already-loaded, reconciled device set.
    # ========================================================================

    active_findings = [
        finding
        for finding in existing_findings
        if finding.status in (
            FindingStatus.OPEN,
            FindingStatus.IN_PROGRESS,
        )
    ]

    return active_findings


# ============================================================================
# NETWORK POSTURE
# ============================================================================


@router.get(
    "/posture",
    response_model=NetworkPostureResult,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated global defensive security posture",
)
async def get_network_posture(
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> NetworkPostureResult:
    """
    Compute deterministic defensive security posture.

    Ownership rules:

    - Normal authenticated users:
        only their own devices.

    - Superusers:
        all devices.

    - Anonymous users:
        only unowned devices.
    """

    # ========================================================================
    # 1. Load devices
    # ========================================================================

    stmt = (
        select(Device)
        .options(
            selectinload(Device.ports),
            selectinload(Device.findings),
            selectinload(Device.events),
        )
    )

    # ========================================================================
    # 2. Ownership filtering
    # ========================================================================

    if current_user is None:

        # Anonymous users can only access unowned devices.
        stmt = stmt.where(
            Device.user_id.is_(None)
        )

    elif current_user.is_superuser:

        # Superuser can access every device.
        pass

    else:

        # Normal users can ONLY access their own devices.
        stmt = stmt.where(
            Device.user_id == current_user.id
        )

    # ========================================================================
    # 3. Execute query
    # ========================================================================

    result = await db.execute(stmt)

    devices = (
        result.scalars()
        .unique()
        .all()
    )

    # ========================================================================
    # 4. Calculate risk
    # ========================================================================

    device_results: List[DeviceRiskResult] = []

    for device in devices:

        active_findings = await _generate_and_persist_findings(
            db=db,
            device=device,
        )

        risk_result = (
            RiskCalculator.calculate_device_risk(
                device_id=device.id,
                open_ports=device.ports,
                events=device.events,
                existing_findings=active_findings,
            )
        )

        device_results.append(
            risk_result
        )

    # ========================================================================
    # 5. Commit finding reconciliation
    # ========================================================================

    await db.commit()

    # ========================================================================
    # 6. Calculate network posture
    # ========================================================================

    return RiskCalculator.calculate_network_posture(
        device_results
    )


# ============================================================================
# SINGLE DEVICE RISK
# ============================================================================


@router.get(
    "/devices/{device_id}",
    response_model=DeviceRiskResult,
    status_code=status.HTTP_200_OK,
    summary="Get deterministic risk assessment for a specific device",
)
async def get_device_risk(
    device_id: str,
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> DeviceRiskResult:
    """
    Calculate deterministic risk for one device.

    Includes:

    - Exposure analysis
    - Vulnerability analysis
    - Anomaly analysis
    - Persisted security findings
    - Finding reconciliation
    - Evidence
    - Risk score breakdown
    - RiskAssessment persistence
    - IDOR protection
    """

    # ========================================================================
    # 1. Validate UUID
    # ========================================================================

    try:
        dev_uuid = uuid.UUID(device_id)

    except (
        ValueError,
        AttributeError,
    ):

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid UUID format: {device_id}"
            ),
        )

    # ========================================================================
    # 2. Load device
    # ========================================================================

    stmt = (
        select(Device)
        .where(
            Device.id == dev_uuid
        )
        .options(
            selectinload(Device.ports),
            selectinload(Device.findings),
            selectinload(Device.events),
        )
    )

    result = await db.execute(stmt)

    device = result.scalar_one_or_none()

    # ========================================================================
    # 3. Device not found
    # ========================================================================

    if device is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Device with id '{device_id}' "
                "was not found."
            ),
        )

    # ========================================================================
    # 4. STRICT IDOR / OWNERSHIP PROTECTION
    # ========================================================================

    """
    Authorization policy:

    Anonymous:
        only unowned devices.

    Normal authenticated user:
        only devices where device.user_id == current_user.id.

    Superuser:
        all devices.
    """

    if current_user is None:

        # Anonymous access to an owned device is forbidden.
        if device.user_id is not None:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Device with id '{device_id}' "
                    "was not found."
                ),
            )

    elif current_user.is_superuser:

        # Superuser is allowed.
        pass

    elif device.user_id != current_user.id:

        # ------------------------------------------------------------------
        # Return 404 instead of 403.
        #
        # This prevents an attacker from learning whether another
        # user's device UUID actually exists.
        # ------------------------------------------------------------------

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Device with id '{device_id}' "
                "was not found."
            ),
        )

    # ========================================================================
    # 5. Generate + persist + reconcile findings
    # ========================================================================

    await _generate_and_persist_findings(
        db=db,
        device=device,
    )

    # ========================================================================
    # 6. Reload findings
    # ========================================================================

    await db.refresh(
        device,
        attribute_names=[
            "findings",
        ],
    )

    # ========================================================================
    # 7. Active findings only
    # ========================================================================

    active_findings = [
        finding
        for finding in device.findings
        if finding.status
        in (
            FindingStatus.OPEN,
            FindingStatus.IN_PROGRESS,
        )
    ]

    # ========================================================================
    # 8. Calculate device risk
    # ========================================================================

    risk_result = (
        RiskCalculator.calculate_device_risk(
            device_id=device.id,
            open_ports=device.ports,
            events=device.events,
            existing_findings=active_findings,
        )
    )

    # ========================================================================
    # 9. Persist RiskAssessment
    # ========================================================================

    assessment = RiskAssessment(
        device_id=device.id,

        user_id=(
            current_user.id
            if current_user is not None
            else device.user_id
        ),

        overall_score=(
            risk_result.overall_score
        ),

        exposure_subscore=(
            risk_result.exposure_subscore
        ),

        vulnerability_subscore=(
            risk_result.vulnerability_subscore
        ),

        anomaly_subscore=(
            risk_result.anomaly_subscore
        ),

        critical_findings_count=(
            risk_result.critical_findings_count
        ),

        high_findings_count=(
            risk_result.high_findings_count
        ),

        open_risky_ports_count=(
            risk_result.open_risky_ports_count
        ),

        score_breakdown=(
            risk_result.score_breakdown
        ),

        summary_notes=(
            risk_result.summary_notes
        ),
    )

    db.add(assessment)

    # ========================================================================
    # 10. Commit
    # ========================================================================

    await db.commit()

    # ========================================================================
    # 11. Return risk result
    # ========================================================================

    return risk_result