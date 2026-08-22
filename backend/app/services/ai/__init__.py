"""AI Security Advisor service package using NVIDIA Nemotron."""

from app.services.ai.base import BaseAIAdvisor
from app.services.ai.nemotron_client import NemotronClient
from app.services.ai.service import AIService, ai_service
from app.services.ai.schemas import (
    AIChatRequest,
    AIChatResponse,
    AITriageRequest,
    AITriageResponse,
    AIThreatAnalysis,
    DeviceRiskExplanation,
    FindingExplanation,
    HardeningGuideResponse,
    HardeningItem,
    TelemetryExplanation,
)
from app.services.ai.sanitizer import (
    AIValidationError,
    extract_and_validate_json,
    sanitize_device_data,
    sanitize_text,
)

__all__ = [
    "BaseAIAdvisor",
    "NemotronClient",
    "AIService",
    "ai_service",
    "AIChatRequest",
    "AIChatResponse",
    "AITriageRequest",
    "AITriageResponse",
    "AIThreatAnalysis",
    "DeviceRiskExplanation",
    "FindingExplanation",
    "HardeningGuideResponse",
    "HardeningItem",
    "TelemetryExplanation",
    "AIValidationError",
    "extract_and_validate_json",
    "sanitize_device_data",
    "sanitize_text",
]

