"""Security finding API endpoints with resource ownership enforcement."""

from typing import List

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.device import Device
from app.models.enums import FindingStatus
from app.models.security_finding import SecurityFinding
from app.models.user import User
from app.schemas.security_finding import SecurityFindingResponse

router = APIRouter(
    prefix="/findings",
    tags=["Security Findings"],
)


@router.get(
    "",
    response_model=List[SecurityFindingResponse],
    status_code=status.HTTP_200_OK,
    summary="List security findings for the authenticated user",
)
async def list_findings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[SecurityFindingResponse]:
    """Return findings belonging to devices visible to the current user."""
    stmt = (
        select(SecurityFinding)
        .join(Device, SecurityFinding.device_id == Device.id)
        .where(
            SecurityFinding.status.in_(
                (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
            )
        )
        .order_by(SecurityFinding.created_at.desc())
    )

    if not current_user.is_superuser:
        stmt = stmt.where(Device.user_id == current_user.id)

    result = await db.execute(stmt)
    findings = result.scalars().all()

    return [
        SecurityFindingResponse.model_validate(finding)
        for finding in findings
    ]
