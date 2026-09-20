"""Scan execution and management API endpoints with resource ownership enforcement."""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    get_db,
    get_optional_current_user,
    rate_limit_scans,
)
from app.core.exceptions import ScopeValidationError
from app.core.security import validate_user_target_scope
from app.db.session import AsyncSessionLocal
from app.models.enums import ScanStatus, ScanType
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.scan_job import ScanJobResponse
from app.services.discovery.models import (
    DiscoveryResult,
    DryRunResult,
)
from app.services.discovery.service import DiscoveryService


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)

_scan_tasks: set[asyncio.Task[None]] = set()


class ScanRequest(BaseModel):
    """Scan creation request payload."""

    target_subnet: str = Field(
        ...,
        description=(
            "Target RFC 1918 private IPv4 subnet or host "
            "(e.g. 192.168.1.0/24 or 192.168.1.50)"
        ),
    )

    scan_type: ScanType = Field(
        default=ScanType.DISCOVERY,
        description="Scan depth/type",
    )

    dry_run: bool = Field(
        default=False,
        description="Dry-run simulation mode (zero network sockets)",
    )

    ports: Optional[List[int]] = Field(
        default=None,
        description="Optional custom list of defensive ports (1-65535)",
    )

    @field_validator("scan_type", mode="before")
    @classmethod
    def parse_scan_type(cls, value: Any) -> Any:
        """Normalize scan type strings and UI aliases to the ScanType enum."""
        if isinstance(value, str):
            value_upper = value.strip().upper()
            aliases = {
                "PORT_PROFILE": ScanType.STANDARD_AUDIT,
                "PORTPROFILE": ScanType.STANDARD_AUDIT,
                "PORTS": ScanType.STANDARD_AUDIT,
                "SERVICE": ScanType.STANDARD_AUDIT,
                "SERVICES": ScanType.STANDARD_AUDIT,
                "STANDARD": ScanType.STANDARD_AUDIT,
                "FULL": ScanType.DEEP_PROFILE,
                "DEEP": ScanType.DEEP_PROFILE,
                "COMPREHENSIVE": ScanType.DEEP_PROFILE,
                "AUDIT": ScanType.DEEP_PROFILE,
                "QUICK": ScanType.DISCOVERY,
                "ARP": ScanType.DISCOVERY,
                "ICMP": ScanType.DISCOVERY,
            }
            if value_upper in aliases:
                return aliases[value_upper]

            if hasattr(ScanType, value_upper):
                return getattr(ScanType, value_upper)

        return value


class ScanExecutionResponse(BaseModel):
    """Response returning scan job and execution results."""

    scan_job: ScanJobResponse
    dry_run_result: Optional[DryRunResult] = None
    discovery_result: Optional[DiscoveryResult] = None


async def _execute_scan_job(
    scan_job_id: uuid.UUID,
    target_subnet: str,
    scan_type: ScanType,
    dry_run: bool,
    ports: Optional[List[int]],
    owner_user_id: Optional[uuid.UUID],
) -> None:
    """Execute a persisted scan job outside the request lifecycle."""

    # Select appropriate defensive ports according to scan strategy if not explicitly passed:
    if ports is None:
        if scan_type == ScanType.STANDARD_AUDIT:
            ports = [21, 22, 23, 53, 80, 443, 445, 554, 631, 8080, 8443, 8888]
        elif scan_type == ScanType.DEEP_PROFILE:
            ports = [
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631,
                993, 995, 1433, 1883, 3306, 3389, 5000, 5432, 5900, 8000, 8080,
                8443, 8554, 8888, 9000
            ]

    async with AsyncSessionLocal() as db:
        try:
            await DiscoveryService().execute_discovery(
                target_str=target_subnet,
                ports=ports,
                dry_run=dry_run,
                db=db,
                scan_job_id=scan_job_id,
                owner_user_id=owner_user_id,
            )
        except Exception as exc:
            scan_job = await db.get(ScanJob, scan_job_id)
            if scan_job is not None:
                scan_job.status = ScanStatus.FAILED
                scan_job.error_message = str(exc)
                scan_job.completed_at = datetime.now(timezone.utc)
                await db.commit()


def _schedule_scan_job(
    scan_job_id: uuid.UUID,
    target_subnet: str,
    scan_type: ScanType,
    dry_run: bool,
    ports: Optional[List[int]],
    owner_user_id: Optional[uuid.UUID],
) -> None:
    """Schedule a scan without holding open the HTTP request."""

    task = asyncio.create_task(
        _execute_scan_job(
            scan_job_id,
            target_subnet,
            scan_type,
            dry_run,
            ports,
            owner_user_id,
        )
    )
    _scan_tasks.add(task)
    task.add_done_callback(_scan_tasks.discard)


@router.get(
    "",
    response_model=List[ScanJobResponse],
    status_code=status.HTTP_200_OK,
    summary="List past defensive scans",
)
async def list_scans(
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> List[ScanJobResponse]:
    """
    List historical scan jobs.

    Authenticated users can see:
    - Their own scan jobs.
    - Explicitly unowned/global scan jobs.

    Superusers can see all scan jobs.
    """

    stmt = select(ScanJob).order_by(
        ScanJob.created_at.desc()
    )

    if current_user and not current_user.is_superuser:
        stmt = stmt.where(
            (ScanJob.user_id == current_user.id)
            | (ScanJob.user_id.is_(None))
        )

    result = await db.execute(stmt)

    scans = result.scalars().all()

    return [
        ScanJobResponse.model_validate(scan)
        for scan in scans
    ]


@router.post(
    "",
    response_model=ScanJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a defensive network discovery scan",
    dependencies=[Depends(rate_limit_scans)],
)
async def create_scan(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """
    Validate target scope and execute defensive discovery.

    Only authorized RFC 1918 private IPv4 networks are permitted:

    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

    The authenticated user's ID is propagated into the discovery
    service so discovered devices can be associated with the
    correct owner.
    """

    # ============================================================
    # 1. VALIDATE RFC 1918 TARGET SCOPE
    # ============================================================

    try:
        validate_user_target_scope(
            request.target_subnet,
            current_user.authorized_network_scope,
        )

    except ScopeValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Defensive Scope Violation: "
                f"{str(exc)}"
            ),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid target format: "
                f"{str(exc)}"
            ),
        ) from exc

    # ============================================================
    # 2. DETERMINE AUTHENTICATED OWNER
    # ============================================================

    owner_user_id = current_user.id

    # ============================================================
    # 3. CREATE SCAN JOB
    # ============================================================

    now = datetime.now(timezone.utc)

    scan_job = ScanJob(
        id=uuid.uuid4(),
        user_id=owner_user_id,
        target_subnet=request.target_subnet.strip(),
        scan_type=request.scan_type,
        status=ScanStatus.RUNNING,
        devices_found=0,
        ports_scanned=0,
        started_at=now,
        summary_findings={},
        error_message="",
    )

    db.add(scan_job)

    await db.commit()
    await db.refresh(scan_job)

    # ============================================================
    # 4. SCHEDULE DEFENSIVE DISCOVERY
    # ============================================================

    _schedule_scan_job(
        scan_job.id,
        request.target_subnet,
        request.scan_type,
        request.dry_run,
        request.ports,
        owner_user_id,
    )

    return ScanJobResponse.model_validate(scan_job)


@router.get(
    "/{scan_id}",
    response_model=ScanJobResponse,
    summary="Get scan job status and details",
)
async def get_scan(
    scan_id: uuid.UUID,

    # IMPORTANT:
    # This endpoint accesses a specific private resource.
    # Authentication is therefore REQUIRED.
    current_user: User = Depends(get_current_user),

    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """
    Retrieve a scan job by ID.

    IDOR protection:

    - Normal users can access only their own scan jobs.
    - Explicitly unowned/global scan jobs may be accessed.
    - Superusers can access all scan jobs.
    - Unauthorized resources return 404 rather than 403.

    Authentication is mandatory for this endpoint.
    """

    # ============================================================
    # 1. FIND SCAN JOB
    # ============================================================

    query = select(ScanJob).where(
        ScanJob.id == scan_id
    )

    result = await db.execute(query)

    scan_job = result.scalar_one_or_none()

    if not scan_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Scan job with ID {scan_id} "
                "not found."
            ),
        )

    # ============================================================
    # 2. IDOR / RESOURCE OWNERSHIP PROTECTION
    # ============================================================

    if (
        not current_user.is_superuser
        and scan_job.user_id is not None
        and scan_job.user_id != current_user.id
    ):
        # Return 404 rather than 403.
        #
        # This prevents another user from learning whether
        # the resource exists.

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Scan job with ID {scan_id} "
                "not found."
            ),
        )

    # ============================================================
    # 3. RETURN AUTHORIZED RESOURCE
    # ============================================================

    return ScanJobResponse.model_validate(
        scan_job
    )