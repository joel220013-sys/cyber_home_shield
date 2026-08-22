"""Risk Engine data transfer models and schemas."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import FindingStatus, Protocol, Severity


class BaselineStatus(str, Enum):
    """Anomaly detection status against established baseline."""
    NORMAL = "normal"
    ELEVATED = "elevated"
    ANOMALOUS = "anomalous"
    SEVERE_ANOMALY = "severe_anomaly"
    INSUFFICIENT_DATA = "insufficient_data"

    def __str__(self) -> str:
        return self.value


class FindingCategory(str, Enum):
    """Categorization for defensive security findings."""
    EXPOSURE = "EXPOSURE"
    CONFIGURATION = "CONFIGURATION"
    SERVICE = "SERVICE"
    ANOMALY = "ANOMALY"
    AUTHENTICATION = "AUTHENTICATION"
    OTHER = "OTHER"

    def __str__(self) -> str:
        return self.value


class FindingEvidence(BaseModel):
    """Diagnostic evidence supporting a security finding."""
    source: str = Field(..., description="Evidence origin (e.g., 'open_port', 'anomaly_detector', 'banner')")
    port: Optional[int] = Field(default=None, description="Port number if applicable")
    protocol: Optional[str] = Field(default=None, description="Protocol name")
    reason: str = Field(..., description="Observed factual reason")
    raw_data: Optional[str] = Field(default=None, description="Diagnostic banner or payload trace")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(frozen=True)


class EvaluatedFinding(BaseModel):
    """Internal generated finding structure before or during persistence."""
    finding_id: Optional[uuid.UUID] = None
    device_id: uuid.UUID
    title: str
    category: str
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation_steps: str = ""
    cve_id: str = ""


class ExposureResult(BaseModel):
    """Outcome of device service exposure evaluation."""
    exposure_score: float = Field(..., ge=0.0, le=100.0)
    open_ports_count: int = Field(default=0, ge=0)
    risky_services_count: int = Field(default=0, ge=0)
    service_exposures: List[Dict[str, Any]] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)


class AnomalyBaseline(BaseModel):
    """Summary of baseline metrics for an evaluated telemetry window."""
    baseline_window_seconds: float = 3600.0
    event_count: int = 0
    known_destination_ports: List[int] = Field(default_factory=list)
    known_protocols: List[str] = Field(default_factory=list)
    average_event_rate: float = 0.0  # events per minute
    current_event_rate: float = 0.0  # events per minute
    deviation: float = 0.0
    status: BaselineStatus = BaselineStatus.INSUFFICIENT_DATA
    reasons: List[str] = Field(default_factory=list)


class AnomalyResult(BaseModel):
    """Outcome of telemetry anomaly detection for a device."""
    anomaly_score: float = Field(..., ge=0.0, le=100.0)
    status: BaselineStatus
    anomalies_detected: List[Dict[str, Any]] = Field(default_factory=list)
    events_analyzed: int = 0
    baseline: AnomalyBaseline = Field(default_factory=AnomalyBaseline)


class VulnerabilityResult(BaseModel):
    """Outcome of security finding and vulnerability scoring."""
    vulnerability_score: float = Field(..., ge=0.0, le=100.0)
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    reasons: List[str] = Field(default_factory=list)


class DeviceRiskResult(BaseModel):
    """Full deterministic risk assessment result for a single device."""
    device_id: uuid.UUID
    overall_score: float = Field(..., ge=0.0, le=100.0)
    exposure_subscore: float = Field(..., ge=0.0, le=100.0)
    vulnerability_subscore: float = Field(..., ge=0.0, le=100.0)
    anomaly_subscore: float = Field(..., ge=0.0, le=100.0)
    critical_findings_count: int = 0
    high_findings_count: int = 0
    open_risky_ports_count: int = 0
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    summary_notes: str = ""
    findings: List[EvaluatedFinding] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NetworkPostureResult(BaseModel):
    """Aggregated deterministic security posture across all network devices."""
    network_risk_score: float = Field(..., ge=0.0, le=100.0)
    total_devices: int = Field(default=0, ge=0)
    vulnerable_devices: int = Field(default=0, ge=0)
    critical_findings: int = Field(default=0, ge=0)
    high_findings: int = Field(default=0, ge=0)
    medium_findings: int = Field(default=0, ge=0)
    low_findings: int = Field(default=0, ge=0)
    active_anomalies: int = Field(default=0, ge=0)
    device_scores: Dict[str, float] = Field(default_factory=dict)
    posture_breakdown: Dict[str, Any] = Field(default_factory=dict)
    last_evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

