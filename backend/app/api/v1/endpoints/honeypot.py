"""Honeypot Deception Subsystem API Endpoints."""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_db,
    get_current_user,
    rate_limit_honeypot,
)
from app.core.exceptions import ScopeValidationError
from app.models.enums import Severity
from app.models.honeypot_event import HoneypotEvent
from app.models.user import User
from app.schemas.honeypot import (
    HoneypotAnalysisResponse,
    HoneypotEventResponse,
    HoneypotSimulateRequest,
    HoneypotStartRequest,
    HoneypotStartResponse,
    HoneypotStatusResponse,
    HoneypotStopResponse,
)
from app.services.ai.service import ai_service
from app.services.honeypot.event_logger import log_honeypot_event
from app.services.honeypot.manager import honeypot_manager

router = APIRouter(prefix="/honeypot", tags=["Honeypot & Deception"])


@router.get(
    "/status",
    response_model=HoneypotStatusResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def get_honeypot_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> HoneypotStatusResponse:
    """
    Retrieve current honeypot subsystem status, running trap listeners, and telemetry summary.
    """
    # Count user-scoped or global events
    total_query = select(func.count(HoneypotEvent.id))
    high_query = select(func.count(HoneypotEvent.id)).where(
        HoneypotEvent.severity.in_([Severity.HIGH, Severity.CRITICAL])
    )
    last_event_query = select(HoneypotEvent.event_timestamp).order_by(
        HoneypotEvent.event_timestamp.desc()
    ).limit(1)

    if current_user:
        total_query = total_query.where(HoneypotEvent.user_id == current_user.id)
        high_query = high_query.where(HoneypotEvent.user_id == current_user.id)
        last_event_query = last_event_query.where(HoneypotEvent.user_id == current_user.id)

    total_res = await db.execute(total_query)
    total_events = total_res.scalar() or 0

    high_res = await db.execute(high_query)
    high_events = high_res.scalar() or 0

    last_res = await db.execute(last_event_query)
    last_interaction = last_res.scalar()

    return honeypot_manager.get_status(
        total_events=total_events,
        high_severity_events=high_events,
        last_interaction=last_interaction,
    )


@router.post(
    "/start",
    response_model=HoneypotStartResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def start_honeypot(
    request: Optional[HoneypotStartRequest] = None,
    current_user: User = Depends(get_current_user),
) -> HoneypotStartResponse:
    """
    Start defensive honeypot trap listeners. Enforces localhost isolation by default.
    """
    custom_host = request.bind_host if request else None
    try:
        honeypot_manager.enable()
        active = await honeypot_manager.start(custom_bind_host=custom_host)
        return HoneypotStartResponse(
            status="started",
            running=True,
            bind_host=honeypot_manager.bind_host,
            active_services=active,
            message="Defensive honeypot deception traps activated successfully.",
        )
    except ScopeValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start honeypot traps: {e}",
        )


@router.post(
    "/stop",
    response_model=HoneypotStopResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def stop_honeypot(
    current_user: User = Depends(get_current_user),
) -> HoneypotStopResponse:
    """
    Stop honeypot listeners and release network resources safely.
    """
    try:
        await honeypot_manager.stop()
        honeypot_manager.disable()
        return HoneypotStopResponse(
            status="stopped",
            running=False,
            message="Defensive honeypot traps safely deactivated.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop honeypot traps: {e}",
        )


@router.get(
    "/events",
    response_model=List[HoneypotEventResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def list_honeypot_events(
    severity: Optional[Severity] = Query(None, description="Filter by severity rating"),
    interaction_type: Optional[str] = Query(None, description="Filter by interaction archetype"),
    limit: int = Query(50, ge=1, le=200, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[HoneypotEventResponse]:
    """
    List recorded honeypot deception events with user isolation and filtering.
    """
    query = select(HoneypotEvent).order_by(HoneypotEvent.event_timestamp.desc())

    if not current_user.is_superuser:
        query = query.where(HoneypotEvent.user_id == current_user.id)

    if severity:
        query = query.where(HoneypotEvent.severity == severity)

    if interaction_type:
        query = query.where(HoneypotEvent.interaction_type == interaction_type)

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    events = result.scalars().all()
    return list(events)


@router.get(
    "/events/{event_id}",
    response_model=HoneypotEventResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def get_honeypot_event(
    event_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> HoneypotEventResponse:
    """
    Retrieve single honeypot event detail with IDOR protection.
    """
    try:
        uuid_obj = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event UUID format: {event_id}",
        )

    stmt = select(HoneypotEvent).where(HoneypotEvent.id == uuid_obj)
    res = await db.execute(stmt)
    event = res.scalar_one_or_none()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot event '{event_id}' was not found.",
        )

    if event.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot event '{event_id}' was not found.",
        )

    return event


@router.post(
    "/analyze/{event_id}",
    response_model=HoneypotAnalysisResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def analyze_honeypot_incident(
    event_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> HoneypotAnalysisResponse:
    """
    Trigger NVIDIA Nemotron AI Security Advisor explanation of an intercepted honeypot probe.
    """
    try:
        uuid_obj = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event UUID format: {event_id}",
        )

    # Ownership check
    stmt = select(HoneypotEvent).where(HoneypotEvent.id == uuid_obj)
    res = await db.execute(stmt)
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot event '{event_id}' was not found.",
        )

    if event.user_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Honeypot event '{event_id}' was not found.",
        )

    user_id = current_user.id if current_user else None
    return await ai_service.explain_honeypot(str(uuid_obj), db, user_id=user_id)


@router.post(
    "/simulate",
    response_model=HoneypotEventResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_honeypot)],
)
async def simulate_honeypot_probe(
    request: HoneypotSimulateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> HoneypotEventResponse:
    """
    Safely inject a simulated test probe against a honeypot trap for verification and triage testing.
    """
    user_id = current_user.id

    # Process through manager
    telemetry = await honeypot_manager.handle_simulated_probe(
        trap_type=request.trap_type,
        source_ip=request.source_ip or "192.168.1.188",
        interaction_type=request.interaction_type or "login_attempt",
        endpoint=request.endpoint or "/login",
        user_id=user_id,
    )

    # Persist and run anomaly checks
    saved_event = await log_honeypot_event(db=db, telemetry=telemetry)
    return saved_event

