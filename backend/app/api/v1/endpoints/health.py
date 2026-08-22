"""Health check endpoint."""

from fastapi import APIRouter
from app.config import settings
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Check the operational status of the Cyber Home Shield backend service.",
)
async def health_check() -> HealthResponse:
    """Return service health confirmation."""
    return HealthResponse(
        status="ok",
        service=settings.APP_NAME,
    )

