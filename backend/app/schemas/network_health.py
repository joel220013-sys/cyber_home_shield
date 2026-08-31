"""Schemas for read-only local gateway health checks."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class RouterHealthResponse(BaseModel):
    """Reachability result for the detected gateway only."""

    model_config = ConfigDict(extra="forbid")

    status: str
    gateway_ip: Optional[str] = None
    latency_ms: Optional[float] = None
    checked_at: datetime
    method: Optional[str] = None
