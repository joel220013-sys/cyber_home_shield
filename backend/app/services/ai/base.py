"""Abstract Base AI Security Advisor interface."""

import abc
from typing import Any, Dict, List, Optional
from app.schemas.honeypot import HoneypotAnalysisResponse
from app.services.ai.schemas import (
    AIThreatAnalysis,
    AIChatResponse,
    DeviceRiskExplanation,
    FindingExplanation,
    HardeningGuideResponse,
    TelemetryExplanation,
)


class BaseAIAdvisor(abc.ABC):
    """
    Abstract interface for AI Security Advisor implementations.
    Isolates AI provider logic (NVIDIA Nemotron) from core application services.
    """

    @property
    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Check if AI provider credentials and models are properly configured."""
        raise NotImplementedError

    @abc.abstractmethod
    async def analyze_device_risk(
        self,
        device_data: Dict[str, Any],
        deterministic_score: float,
        score_breakdown: Dict[str, Any],
    ) -> DeviceRiskExplanation:
        """Provide contextual narrative explaining device risk posture."""
        raise NotImplementedError

    @abc.abstractmethod
    async def explain_security_finding(
        self,
        finding_data: Dict[str, Any],
        device_context: Dict[str, Any],
    ) -> FindingExplanation:
        """Explain a security posture finding with defensive remediation."""
        raise NotImplementedError

    @abc.abstractmethod
    async def explain_telemetry_event(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Dict[str, Any],
    ) -> TelemetryExplanation:
        """Triage network telemetry event and explain anomaly indicators."""
        raise NotImplementedError

    @abc.abstractmethod
    async def explain_honeypot_event(
        self,
        event_data: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
    ) -> HoneypotAnalysisResponse:
        """Analyze intercepted honeypot deception telemetry."""
        raise NotImplementedError

    @abc.abstractmethod
    async def generate_hardening_guide(
        self,
        target_type: str,
        observed_services: List[int],
        context: Dict[str, Any],
    ) -> HardeningGuideResponse:
        """Generate safe, defensive hardening guidelines for device or router."""
        raise NotImplementedError

    @abc.abstractmethod
    async def triage_security_event(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Optional[Dict[str, Any]] = None,
    ) -> AIThreatAnalysis:
        """Perform structured defensive triage on security events."""
        raise NotImplementedError

    @abc.abstractmethod
    async def chat_advisory(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> AIChatResponse:
        """Interactive defensive security advisory chat."""
        raise NotImplementedError

