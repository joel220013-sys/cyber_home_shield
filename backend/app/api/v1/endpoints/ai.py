"""AI Security Advisor API endpoints (NVIDIA Nemotron) with rate limiting and IDOR protection."""

import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    get_db,
    get_optional_current_user,
    rate_limit_ai,
)
from app.models.device import Device
from app.models.security_finding import SecurityFinding
from app.models.user import User
from app.services.ai.schemas import (
    AIChatRequest,
    AIChatResponse,
    AITriageRequest,
    AITriageResponse,
    DeviceRiskExplanation,
    FindingExplanation,
    HardeningGuideResponse,
)
from app.services.ai.service import ai_service

router = APIRouter(prefix="/ai", tags=["AI Security Advisor"])


def _require_resource_access(
    owner_id: Optional[uuid.UUID],
    current_user: Optional[User],
    resource_name: str,
) -> None:
    """Reject anonymous or cross-tenant access to an owned resource."""
    if (
        owner_id is not None
        and (
            current_user is None
            or (
                owner_id != current_user.id
                and not current_user.is_superuser
            )
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource_name} was not found.",
        )


class HardeningGuideRequest(BaseModel):
    """Request payload for hardening guidelines."""
    target_type: str = Field(..., description="Target device or service type, e.g. 'ROUTER', 'IOT', 'STORAGE'")
    observed_services: List[int] = Field(default_factory=list, description="List of open port numbers observed")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional device metadata")


@router.post(
    "/triage",
    response_model=AITriageResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_ai)],
)
async def triage_event(
    request: AITriageRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AITriageResponse:
    """
    Perform defensive AI triage on a network telemetry event or finding.
    Returns structured threat evaluation with confidence, observed facts, and recommendations.
    """
    try:
        analysis = await ai_service.triage_event(
            event_data=request.event_data or {},
            anomaly_data=request.finding_data or {},
        )
        return AITriageResponse(
            analysis=analysis,
            ai_available=analysis.confidence > 0,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI triage service encountered an error.",
        )


@router.post(
    "/chat",
    response_model=AIChatResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_ai)],
)
async def chat_advisory(
    request: AIChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AIChatResponse:
    """
    Interactive defensive cybersecurity advisory chat powered by NVIDIA Nemotron.
    Advises on home IoT security, router hardening, finding remediation, and network posture.
    """
    try:
        context_data: Dict[str, Any] = {}
        if request.context_device_id:
            try:
                dev_uuid = uuid.UUID(request.context_device_id)
                stmt = select(Device).where(Device.id == dev_uuid)
                res = await db.execute(stmt)
                dev = res.scalar_one_or_none()
                if dev:
                    _require_resource_access(
                        dev.user_id,
                        current_user,
                        "Device",
                    )
                    context_data = {
                        "device_id": str(dev.id),
                        "ip_address": dev.ip_address,
                        "device_type": str(dev.device_type),
                    }
            except ValueError:
                pass

        return await ai_service.chat(
            message=request.message,
            history=request.history,
            context=context_data,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI chat advisor encountered an unexpected error.",
        )


@router.post(
    "/explain-device/{device_id}",
    response_model=DeviceRiskExplanation,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_ai)],
)
async def explain_device_risk(
    device_id: str,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
) -> DeviceRiskExplanation:
    """
    Generate contextual AI narrative explaining why a device received its deterministic risk score.
    Enforces device ownership to prevent IDOR access.
    """
    try:
        uuid_obj = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid device UUID format: {device_id}",
        )

    # Check ownership
    stmt = select(Device).where(Device.id == uuid_obj)
    res = await db.execute(stmt)
    dev = res.scalar_one_or_none()
    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device with id '{device_id}' was not found.",
        )

    _require_resource_access(dev.user_id, current_user, "Device")

    return await ai_service.explain_device(str(uuid_obj), db)


@router.post(
    "/explain-finding/{finding_id}",
    response_model=FindingExplanation,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_ai)],
)
async def explain_security_finding(
    finding_id: str,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingExplanation:
    """
    Explain a specific security posture finding with defensive remediation guidance.
    Enforces finding ownership to prevent IDOR access.
    """
    try:
        uuid_obj = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding UUID format: {finding_id}",
        )

    stmt = select(SecurityFinding).where(SecurityFinding.id == uuid_obj)
    res = await db.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with id '{finding_id}' was not found.",
        )

    # Check parent device ownership
    dev_stmt = select(Device).where(Device.id == finding.device_id)
    dev_res = await db.execute(dev_stmt)
    dev = dev_res.scalar_one_or_none()
    _require_resource_access(
        dev.user_id if dev else None,
        current_user,
        "Finding",
    )

    return await ai_service.explain_finding(str(uuid_obj), db)


@router.post(
    "/hardening-guide",
    response_model=HardeningGuideResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_ai)],
)
async def generate_hardening_guide(
    request: HardeningGuideRequest,
    current_user: User = Depends(get_current_user),
) -> HardeningGuideResponse:
    """
    Generate actionable step-by-step defensive hardening guide for a device type or open services.
    """
    return await ai_service.generate_hardening(
        target_type=request.target_type,
        observed_services=request.observed_services,
        context=request.context,
    )

