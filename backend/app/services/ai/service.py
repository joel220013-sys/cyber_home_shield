"""AI Security Advisor application service coordinating models, database, and telemetry."""

import time
import uuid as _uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.device import Device
from app.models.honeypot_event import HoneypotEvent
from app.models.network_event import NetworkEvent
from app.models.security_finding import SecurityFinding
from app.schemas.honeypot import HoneypotAnalysisResponse
from app.services.ai.base import BaseAIAdvisor
from app.services.ai.nemotron_client import NemotronClient
from app.services.ai.schemas import (
    AIChatResponse,
    AIThreatAnalysis,
    DeviceRiskExplanation,
    FindingExplanation,
    HardeningGuideResponse,
    TelemetryExplanation,
)
from app.services.risk_engine.calculator import RiskCalculator

_HONEYPOT_EXPLAIN_CACHE: Dict[str, Tuple[float, HoneypotAnalysisResponse]] = {}
_CACHE_TTL_SECONDS = 600.0  # 10 minutes cache


class AIService:
    """High-level service coordinating AI advisor requests with database context."""

    def __init__(self, advisor: Optional[BaseAIAdvisor] = None):
        self.advisor = advisor or NemotronClient()

    async def explain_device(self, device_id: str, db: AsyncSession) -> DeviceRiskExplanation:
        """Fetch device, compute deterministic risk, and generate AI narrative explanation."""
        try:
            target_uuid = _uuid.UUID(str(device_id))
        except (ValueError, AttributeError):
            target_uuid = device_id

        query = (
            select(Device)
            .where(Device.id == target_uuid)
            .options(
                selectinload(Device.ports),
                selectinload(Device.findings),
                selectinload(Device.events),
            )
        )
        res = await db.execute(query)
        device = res.scalar_one_or_none()
        if not device:
            return DeviceRiskExplanation(
                device_id=str(target_uuid),
                deterministic_risk_score=0.0,
                key_observations=["Device not found in inventory."],
                risk_factors_explained=[],
                likely_security_implications="Unknown device.",
                defensive_priorities=["Enroll device to calculate risk posture."],
                ai_available=False,
            )

        # 1. Compute deterministic score (source of truth)
        risk_result = RiskCalculator.calculate_device_risk(
            device_id=device.id,
            open_ports=list(device.ports),
            existing_findings=list(device.findings),
            events=list(device.events),
        )

        device_dict = {
            "id": str(device.id),
            "ip_address": device.ip_address,
            "hostname": device.hostname,
            "device_type": device.device_type.value if hasattr(device.device_type, "value") else str(device.device_type),
            "ports": [p.port_number for p in device.ports],
            "findings": [
                {"title": f.title, "severity": f.severity.value, "category": f.category}
                for f in device.findings
            ],
        }

        # 2. Query AI advisor for narrative explanation
        return await self.advisor.analyze_device_risk(
            device_data=device_dict,
            deterministic_score=risk_result.overall_score,
            score_breakdown=risk_result.score_breakdown,
        )

    async def explain_finding(self, finding_id: str, db: AsyncSession) -> FindingExplanation:
        """Fetch finding and device context to generate AI explanation."""
        try:
            target_uuid = _uuid.UUID(str(finding_id))
        except (ValueError, AttributeError):
            target_uuid = finding_id

        query = (
            select(SecurityFinding)
            .where(SecurityFinding.id == target_uuid)
            .options(selectinload(SecurityFinding.device))
        )
        res = await db.execute(query)
        finding = res.scalar_one_or_none()
        if not finding:
            return FindingExplanation(
                title="Finding Not Found",
                severity="MEDIUM",
                explanation="The requested security finding was not found.",
                potential_impact="Unknown",
                ai_available=False,
            )

        finding_dict = {
            "id": str(finding.id),
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "description": finding.description,
            "evidence": getattr(finding, "evidence", [finding.description]),
            "remediation_steps": [finding.remediation_steps] if isinstance(finding.remediation_steps, str) else (finding.remediation_steps or []),
        }

        device_dict = {}
        if finding.device:
            device_dict = {
                "id": str(finding.device.id),
                "ip_address": finding.device.ip_address,
                "device_type": finding.device.device_type.value if hasattr(finding.device.device_type, "value") else str(finding.device.device_type),
            }

        return await self.advisor.explain_security_finding(
            finding_data=finding_dict,
            device_context=device_dict,
        )

    async def explain_honeypot(
        self,
        event_id: str,
        db: AsyncSession,
        user_id: Optional[_uuid.UUID] = None,
    ) -> HoneypotAnalysisResponse:
        """Fetch honeypot event and recent context to generate NVIDIA Nemotron explanation."""
        try:
            target_uuid = _uuid.UUID(str(event_id))
        except (ValueError, AttributeError):
            target_uuid = event_id

        query = select(HoneypotEvent).where(HoneypotEvent.id == target_uuid)
        if user_id:
            query = query.where(HoneypotEvent.user_id == user_id)

        res = await db.execute(query)
        event = res.scalar_one_or_none()
        if not event:
            return HoneypotAnalysisResponse(
                event_id=target_uuid if isinstance(target_uuid, _uuid.UUID) else _uuid.uuid4(),
                summary="Honeypot event not found.",
                pattern_detected="Unknown",
                severity="LOW",
                defensive_implications=["Event record unavailable."],
                recommended_actions=["Ensure event ID is correct."],
                confidence=0.0,
                model_used="NVIDIA Nemotron (Unavailable)",
            )

        # Check TTL cache to prevent flooding LLM on repeated scans
        cache_key = f"{event.honeypot_id}:{event.interaction_type}:{event.endpoint}"
        now = time.time()
        if cache_key in _HONEYPOT_EXPLAIN_CACHE:
            ts, cached_resp = _HONEYPOT_EXPLAIN_CACHE[cache_key]
            if now - ts < _CACHE_TTL_SECONDS:
                return HoneypotAnalysisResponse(
                    event_id=event.id,
                    summary=cached_resp.summary,
                    pattern_detected=cached_resp.pattern_detected,
                    severity=cached_resp.severity,
                    defensive_implications=cached_resp.defensive_implications,
                    recommended_actions=cached_resp.recommended_actions,
                    confidence=cached_resp.confidence,
                    model_used=cached_resp.model_used,
                )

        # Fetch recent events from same source IP for context
        recent_query = (
            select(HoneypotEvent)
            .where(
                HoneypotEvent.source_ip == event.source_ip,
                HoneypotEvent.id != event.id,
            )
            .order_by(HoneypotEvent.event_timestamp.desc())
            .limit(5)
        )
        if user_id:
            recent_query = recent_query.where(HoneypotEvent.user_id == user_id)

        recent_res = await db.execute(recent_query)
        recent_events = recent_res.scalars().all()

        event_dict = {
            "id": str(event.id),
            "honeypot_id": event.honeypot_id,
            "source_ip": event.source_ip,
            "destination_port": event.destination_port,
            "interaction_type": event.interaction_type,
            "endpoint": event.endpoint,
            "payload_sample": event.payload_sample,
            "severity": event.severity.value if hasattr(event.severity, "value") else str(event.severity),
        }

        recent_list = [
            {
                "honeypot_id": r.honeypot_id,
                "interaction_type": r.interaction_type,
                "endpoint": r.endpoint,
                "timestamp": r.event_timestamp.isoformat(),
            }
            for r in recent_events
        ]

        result = await self.advisor.explain_honeypot_event(
            event_data=event_dict,
            recent_events=recent_list,
        )
        if result and result.confidence > 0:
            _HONEYPOT_EXPLAIN_CACHE[cache_key] = (now, result)

        return result

    async def triage_event(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Optional[Dict[str, Any]] = None,
    ) -> AIThreatAnalysis:
        """Perform structured defensive triage on a network telemetry event."""
        return await self.advisor.triage_security_event(
            event_data=event_data,
            anomaly_data=anomaly_data,
        )

    async def generate_hardening(
        self,
        target_type: str,
        observed_services: List[int],
        context: Optional[Dict[str, Any]] = None,
    ) -> HardeningGuideResponse:
        """Generate defensive hardening guidelines."""
        return await self.advisor.generate_hardening_guide(
            target_type=target_type,
            observed_services=observed_services,
            context=context or {},
        )

    async def chat(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> AIChatResponse:
        """Defensive conversational security advisory."""
        return await self.advisor.chat_advisory(
            message=message,
            history=history,
            context=context,
        )


# Global AI Service instance
ai_service = AIService()

