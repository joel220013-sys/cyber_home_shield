"""Health check schemas."""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="ok", description="Service health status")
    service: str = Field(default="Cyber Home Shield", description="Service name")
