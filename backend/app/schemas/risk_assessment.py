"""Risk assessment Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RiskAssessmentBase(BaseModel):
    """Base schema for risk posture evaluation."""

    overall_score: float = Field(..., ge=0.0, le=100.0, description="Overall risk index (0.0 to 100.0)")
    exposure_subscore: float = Field(default=0.0, ge=0.0, le=100.0, description="Exposure factor")
    vulnerability_subscore: float = Field(default=0.0, ge=0.0, le=100.0, description="Vulnerability factor")
    anomaly_subscore: float = Field(default=0.0, ge=0.0, le=100.0, description="Anomaly factor")
    critical_findings_count: int = Field(default=0, ge=0)
    high_findings_count: int = Field(default=0, ge=0)
    open_risky_ports_count: int = Field(default=0, ge=0)
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    summary_notes: str = Field(default="", max_length=500)


class RiskAssessmentCreate(RiskAssessmentBase):
    """Schema for recording a computed risk assessment."""

    device_id: Optional[uuid.UUID] = None


class RiskAssessmentResponse(RiskAssessmentBase):
    """Schema for returning risk assessment results."""

    id: uuid.UUID
    device_id: Optional[uuid.UUID] = None
    evaluated_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkPostureSummary(BaseModel):
    """Aggregated global network posture summary."""

    network_risk_score: float = Field(..., ge=0.0, le=100.0)
    total_devices: int = Field(default=0, ge=0)
    vulnerable_devices: int = Field(default=0, ge=0)
    critical_findings: int = Field(default=0, ge=0)
    high_findings: int = Field(default=0, ge=0)
    medium_findings: int = Field(default=0, ge=0)
    low_findings: int = Field(default=0, ge=0)
    active_anomalies: int = Field(default=0, ge=0)
    last_evaluated_at: datetime
