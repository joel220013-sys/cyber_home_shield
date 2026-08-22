"""Network telemetry API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.network_event import NetworkEvent
from app.models.user import User
from app.schemas.network_event import NetworkEventResponse

router = APIRouter(prefix="/telemetry", tags=["Network Telemetry"])


@router.get(
    "/events",
    response_model=List[NetworkEventResponse],
    summary="List authenticated user's network telemetry events",
)
async def list_network_events(
    limit: int = Query(100, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[NetworkEventResponse]:
    """Return newest network events owned by the authenticated user."""

    query = (
        select(NetworkEvent)
        .where(NetworkEvent.user_id == current_user.id)
        .order_by(NetworkEvent.event_timestamp.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    return list(result.scalars().all())