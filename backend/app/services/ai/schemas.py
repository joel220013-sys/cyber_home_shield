"""Pydantic schemas for structured AI Nemotron responses, triage, and chat."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import Severity


class AIThreatAnalysis(BaseModel):
    """Structured threat triage analysis from AI Security Advisor."""
    threat_detected: bool = Field(..., description="Whether an active threat or elevated posture risk was detected")
    threat_type: str = Field(..., description="Categorized threat indicator (e.g., 'EXPOSED_ADMIN_INTERFACE')")
    severity: Severity = Field(default=Severity.MEDIUM, description="Defensive severity classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    reason: str = Field(..., description="Factual justification from evidence")
    recommended_action: str = Field(..., description="Immediate defensive priority")
    evidence: List[Any] = Field(default_factory=list, description="Direct supporting facts")
    recommendations: List[str] = Field(default_factory=list, description="Step-by-step mitigation items")

    model_config = ConfigDict(extra="ignore")


class FindingExplanation(BaseModel):
    """Detailed contextual explanation of a security finding."""
    title: str
    severity: Severity
    explanation: str
    potential_impact: str
    observed_facts: List[str] = Field(default_factory=list)
    inferred_risks: List[str] = Field(default_factory=list)
    defensive_recommendations: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    cve_context: str = "No confirmed CVE exploitation observed in telemetry."
    ai_available: bool = True

    model_config = ConfigDict(extra="ignore")


class TelemetryExplanation(BaseModel):
    """Detailed contextual triage of a network telemetry event."""
    event_classification: str
    is_anomaly: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    observed_facts: List[str] = Field(default_factory=list)
    inferred_risks: List[str] = Field(default_factory=list)
    explanation: str
    recommended_action: str
    ai_available: bool = True

    model_config = ConfigDict(extra="ignore")


class HardeningItem(BaseModel):
    """Single defensive hardening guidance action."""
    priority: str = Field(..., description="'CRITICAL', 'HIGH', 'MEDIUM', or 'LOW'")
    action: str = Field(..., description="Clear descriptive action")
    reason: str = Field(..., description="Why this hardening step is needed")
    safe_steps: List[str] = Field(default_factory=list, description="Step-by-step instructions")
    verification_guidance: str = Field(default="", description="How to verify the fix")

    model_config = ConfigDict(extra="ignore")


class HardeningGuideResponse(BaseModel):
    """Comprehensive hardening guide for a device or service."""
    target_type: str
    hardening_items: List[HardeningItem] = Field(default_factory=list)
    summary: str
    ai_available: bool = True

    model_config = ConfigDict(extra="ignore")


class DeviceRiskExplanation(BaseModel):
    """Contextual narrative explaining device risk posture."""
    device_id: str
    deterministic_risk_score: float
    key_observations: List[str] = Field(default_factory=list)
    risk_factors_explained: List[str] = Field(default_factory=list)
    likely_security_implications: str
    defensive_priorities: List[str] = Field(default_factory=list)
    ai_available: bool = True

    model_config = ConfigDict(extra="ignore")


class AIChatRequest(BaseModel):
    """User request for AI defensive cybersecurity advisory."""
    message: str = Field(..., min_length=1, max_length=2000, description="Defensive security query")
    context_device_id: Optional[str] = Field(default=None, description="Optional target device ID for context")
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Prior conversational turns")


class AIChatResponse(BaseModel):
    """Defensive AI advisory response."""
    reply: str
    suggested_followups: List[str] = Field(default_factory=list)
    ai_available: bool = True
    model_name: str = "NVIDIA Nemotron"


class AITriageRequest(BaseModel):
    """Request payload for security event or finding triage."""
    finding_id: Optional[str] = None
    device_id: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = None
    finding_data: Optional[Dict[str, Any]] = None


class AITriageResponse(BaseModel):
    """Consolidated triage response."""
    analysis: AIThreatAnalysis
    ai_available: bool = True
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

