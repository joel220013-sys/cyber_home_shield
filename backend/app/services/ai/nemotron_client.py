"""NVIDIA Nemotron AI Security Advisor client using OpenAI-compatible interface."""

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Type, TypeVar

import openai
from openai import AsyncOpenAI

from app.config import settings
from app.models.enums import Severity
from app.schemas.honeypot import HoneypotAnalysisResponse
from app.services.ai.base import BaseAIAdvisor
from app.services.ai.prompts import (
    SYSTEM_PROMPT_CHAT,
    SYSTEM_PROMPT_SECURITY_ANALYST,
    build_device_risk_prompt,
    build_finding_explanation_prompt,
    build_hardening_guide_prompt,
    build_honeypot_analysis_prompt,
    build_telemetry_triage_prompt,
)
from app.services.ai.sanitizer import (
    AIValidationError,
    extract_and_validate_json,
    sanitize_ai_reply,
    sanitize_device_data,
    sanitize_text,
)
from app.services.ai.schemas import (
    AIChatResponse,
    AIThreatAnalysis,
    DeviceRiskExplanation,
    FindingExplanation,
    HardeningGuideResponse,
    HardeningItem,
    TelemetryExplanation,
)


logger = logging.getLogger(
    "cyber_home_shield.ai.nemotron"
)

T = TypeVar("T")

# NVIDIA Nemotron 3.5 Lightning supports up to 32768
# generated output tokens for this API configuration.
MAX_OUTPUT_TOKENS = 32768


class NemotronClient(BaseAIAdvisor):
    """
    NVIDIA Nemotron AI Security Advisor implementation.

    Uses NVIDIA's OpenAI-compatible API endpoint and provides
    defensive cybersecurity analysis with deterministic fallbacks.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 20.0,
    ):
        self.api_key = (
            api_key
            or settings.NVIDIA_API_KEY
        )

        self.base_url = (
            base_url
            or settings.NVIDIA_BASE_URL
        )

        self.model = (
            model
            or settings.NVIDIA_MODEL
        )

        self.timeout = timeout

        self._client: Optional[AsyncOpenAI] = None

    # ==================================================================
    # Configuration
    # ==================================================================

    @property
    def is_configured(self) -> bool:
        """Return True when NVIDIA credentials and model are configured."""

        return bool(
            self.api_key
            and self.api_key.strip()
            and self.model
            and self.model.strip()
        )

    def _get_client(self) -> AsyncOpenAI:
        """
        Lazily initialize the NVIDIA OpenAI-compatible client.

        Automatic SDK retries are disabled because the application
        has its own structured-response recovery and deterministic
        fallback logic.
        """

        if self._client is None:
            if not self.is_configured:
                raise ValueError(
                    "NVIDIA_API_KEY or NVIDIA_MODEL "
                    "is not configured."
                )

            self._client = AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=self.timeout,
                max_retries=0,
            )

        return self._client

    # ==================================================================
    # NVIDIA request options
    # ==================================================================

    @staticmethod
    def _thinking_options() -> Dict[str, Any]:
        """
        Disable Nemotron reasoning/thinking output.

        This keeps application responses focused on the final answer
        and prevents reasoning content from consuming the output budget.
        """

        return {
            "chat_template_kwargs": {
                "enable_thinking": False,
            }
        }

    # ==================================================================
    # Response normalization
    # ==================================================================

    @staticmethod
    def _message_content_to_text(
        content: Any,
    ) -> str:
        """
        Convert OpenAI-compatible message content into plain text.

        Providers may return either a string or a list of content blocks.
        """

        if content is None:
            return ""

        if isinstance(content, str):
            return content

        if isinstance(content, list):
            parts: List[str] = []

            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                    continue

                if isinstance(item, dict):
                    text = item.get("text")

                    if isinstance(text, str):
                        parts.append(text)
                        continue

                    nested = item.get("content")

                    if isinstance(nested, str):
                        parts.append(nested)

            return "".join(parts)

        return str(content)

    @staticmethod
    def _remove_thinking_blocks(
        text: str,
    ) -> str:
        """
        Remove explicit reasoning/thinking blocks.

        These blocks must never be exposed as application output.
        """

        if not text:
            return ""

        cleaned = re.sub(
            r"<think>.*?</think>",
            "",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        cleaned = re.sub(
            r"<reasoning>.*?</reasoning>",
            "",
            cleaned,
            flags=re.DOTALL | re.IGNORECASE,
        )

        return cleaned.strip()

    @staticmethod
    def _extract_balanced_json_object(
        text: str,
    ) -> Optional[str]:
        """
        Extract the first balanced JSON object.

        Correctly handles braces inside JSON strings.
        """

        if not text:
            return None

        start = text.find("{")

        if start == -1:
            return None

        depth = 0
        in_string = False
        escape = False

        for index in range(
            start,
            len(text),
        ):
            char = text[index]

            if in_string:
                if escape:
                    escape = False

                elif char == "\\":
                    escape = True

                elif char == '"':
                    in_string = False

                continue

            if char == '"':
                in_string = True

            elif char == "{":
                depth += 1

            elif char == "}":
                depth -= 1

                if depth == 0:
                    return text[
                        start:index + 1
                    ]

        return None

    @staticmethod
    def _extract_balanced_json_array(
        text: str,
    ) -> Optional[str]:
        """
        Extract the first balanced JSON array.
        """

        if not text:
            return None

        start = text.find("[")

        if start == -1:
            return None

        depth = 0
        in_string = False
        escape = False

        for index in range(
            start,
            len(text),
        ):
            char = text[index]

            if in_string:
                if escape:
                    escape = False

                elif char == "\\":
                    escape = True

                elif char == '"':
                    in_string = False

                continue

            if char == '"':
                in_string = True

            elif char == "[":
                depth += 1

            elif char == "]":
                depth -= 1

                if depth == 0:
                    return text[
                        start:index + 1
                    ]

        return None

    @classmethod
    def _parse_json_payload(
        cls,
        raw_text: str,
    ) -> Dict[str, Any]:
        """
        Robustly extract a JSON object from model output.

        Handles:

        - pure JSON
        - fenced JSON
        - surrounding explanations
        - thinking blocks
        - nested JSON objects
        """

        if not raw_text or not raw_text.strip():
            raise AIValidationError(
                "NVIDIA Nemotron returned empty structured output."
            )

        cleaned = cls._remove_thinking_blocks(
            raw_text
        )

        if not cleaned:
            raise AIValidationError(
                "NVIDIA Nemotron returned only "
                "reasoning/thinking content."
            )

        # --------------------------------------------------------------
        # 1. Direct JSON
        # --------------------------------------------------------------

        try:
            parsed = json.loads(cleaned)

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            pass

        # --------------------------------------------------------------
        # 2. Markdown code block
        # --------------------------------------------------------------

        code_block_match = re.search(
            r"```(?:json|JSON)?\s*(.*?)\s*```",
            cleaned,
            flags=re.DOTALL,
        )

        if code_block_match:
            code_content = (
                code_block_match
                .group(1)
                .strip()
            )

            try:
                parsed = json.loads(
                    code_content
                )

                if isinstance(parsed, dict):
                    return parsed

            except json.JSONDecodeError:
                pass

            balanced = (
                cls._extract_balanced_json_object(
                    code_content
                )
            )

            if balanced:
                try:
                    parsed = json.loads(
                        balanced
                    )

                    if isinstance(parsed, dict):
                        return parsed

                except json.JSONDecodeError:
                    pass

        # --------------------------------------------------------------
        # 3. Balanced JSON object inside surrounding text
        # --------------------------------------------------------------

        balanced_object = (
            cls._extract_balanced_json_object(
                cleaned
            )
        )

        if balanced_object:
            try:
                parsed = json.loads(
                    balanced_object
                )

                if isinstance(parsed, dict):
                    return parsed

            except json.JSONDecodeError as exc:
                raise AIValidationError(
                    "Malformed JSON in extracted "
                    f"AI response: {exc}"
                ) from exc

        raise AIValidationError(
            "No valid JSON object found in "
            "NVIDIA Nemotron response."
        )

    # ==================================================================
    # Structured response validation
    # ==================================================================

    @classmethod
    def _validate_structured_response(
        cls,
        raw_text: str,
        target_schema: Type[T],
    ) -> T:
        """
        Extract and validate structured AI output.

        Supports both Pydantic v1 and v2.
        """

        # --------------------------------------------------------------
        # Existing project validator
        # --------------------------------------------------------------

        try:
            return extract_and_validate_json(
                raw_text,
                target_schema,
            )

        except Exception as first_error:
            logger.debug(
                "Shared AI JSON validator failed; "
                "using Nemotron JSON extraction: %s",
                str(first_error),
            )

        # --------------------------------------------------------------
        # Local extraction
        # --------------------------------------------------------------

        payload = cls._parse_json_payload(
            raw_text
        )

        try:
            model_validate = getattr(
                target_schema,
                "model_validate",
                None,
            )

            if callable(model_validate):
                return model_validate(payload)

            parse_obj = getattr(
                target_schema,
                "parse_obj",
                None,
            )

            if callable(parse_obj):
                return parse_obj(payload)

        except Exception as exc:
            raise AIValidationError(
                "Nemotron response failed "
                f"schema validation: {exc}"
            ) from exc

        raise AIValidationError(
            "Unsupported Pydantic schema "
            "validation interface."
        )

    @staticmethod
    def _safe_response_preview(
        text: str,
        limit: int = 500,
    ) -> str:
        """
        Return a short diagnostic preview.

        Never logs API credentials.
        """

        if not text:
            return "<empty>"

        normalized = re.sub(
            r"\s+",
            " ",
            text,
        ).strip()

        if len(normalized) > limit:
            return (
                normalized[:limit]
                + "...<truncated>"
            )

        return normalized

    # ==================================================================
    # Core model request
    # ==================================================================

    async def _call_model(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = MAX_OUTPUT_TOKENS,
    ) -> str:
        """
        Send a request to NVIDIA Nemotron.

        Returns raw response text.

        Thinking/reasoning is explicitly disabled so the application
        receives the final answer directly.
        """

        client = self._get_client()

        messages = [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ]

        try:
            response = (
                await client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    extra_body=self._thinking_options(),
                )
            )

            if not response.choices:
                raise AIValidationError(
                    "NVIDIA Nemotron returned no choices."
                )

            message = response.choices[0].message

            if message is None:
                raise AIValidationError(
                    "NVIDIA Nemotron returned "
                    "an empty message."
                )

            content = (
                self._message_content_to_text(
                    getattr(
                        message,
                        "content",
                        None,
                    )
                )
            )

            if not content.strip():
                raise AIValidationError(
                    "NVIDIA Nemotron returned "
                    "an empty response."
                )

            cleaned_content = (
                self._remove_thinking_blocks(
                    content
                )
            )

            if not cleaned_content:
                raise AIValidationError(
                    "NVIDIA Nemotron returned "
                    "only thinking/reasoning content."
                )

            logger.debug(
                "Nemotron response received: "
                "type=%s length=%d",
                type(content).__name__,
                len(content),
            )

            return cleaned_content

        except openai.APITimeoutError:
            logger.warning(
                "Nemotron API request timed out."
            )
            raise

        except openai.RateLimitError:
            logger.warning(
                "Nemotron API rate limit exceeded."
            )
            raise

        except openai.APIStatusError as exc:
            logger.warning(
                "Nemotron API returned status %s.",
                exc.status_code,
            )
            raise

        except openai.APIConnectionError:
            logger.warning(
                "Nemotron API connection failed."
            )
            raise

    # ==================================================================
    # Structured model request
    # ==================================================================

    async def _call_structured_model(
        self,
        system_prompt: str,
        user_prompt: str,
        target_schema: Type[T],
        temperature: float = 0.2,
        max_tokens: int = MAX_OUTPUT_TOKENS,
    ) -> T:
        """
        Call Nemotron and validate structured JSON.

        If the first response cannot be parsed, exactly one recovery
        request is attempted.

        The SDK itself has automatic retries disabled.
        """

        raw_output = await self._call_model(
            system_prompt,
            user_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        try:
            return self._validate_structured_response(
                raw_output,
                target_schema,
            )

        except Exception:
            logger.warning(
                "Nemotron structured response parsing failed: %s",
                self._safe_response_preview(
                    raw_output
                ),
            )

        # --------------------------------------------------------------
        # One recovery request
        # --------------------------------------------------------------

        recovery_prompt = (
            "Return ONLY one valid JSON object.\n"
            "No Markdown.\n"
            "No code fences.\n"
            "No explanation.\n"
            "No <think> blocks.\n"
            "No <reasoning> blocks.\n"
            "Use the actual supplied security telemetry.\n"
            "Return all required fields for the requested schema."
        )

        recovery_messages = [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": (
                    f"{user_prompt}\n\n"
                    "=== JSON RECOVERY ===\n"
                    f"{recovery_prompt}"
                ),
            },
        ]

        client = self._get_client()

        recovered_output = ""

        try:
            response = (
                await client.chat.completions.create(
                    model=self.model,
                    messages=recovery_messages,
                    temperature=0.0,
                    max_tokens=MAX_OUTPUT_TOKENS,
                    extra_body=self._thinking_options(),
                )
            )

            if not response.choices:
                raise AIValidationError(
                    "Nemotron recovery request "
                    "returned no choices."
                )

            message = response.choices[0].message

            if message is None:
                raise AIValidationError(
                    "Nemotron recovery request "
                    "returned no message."
                )

            recovered_output = (
                self._message_content_to_text(
                    getattr(
                        message,
                        "content",
                        None,
                    )
                )
            )

            if not recovered_output.strip():
                raise AIValidationError(
                    "Nemotron recovery request "
                    "returned empty output."
                )

            recovered_output = (
                self._remove_thinking_blocks(
                    recovered_output
                )
            )

            if not recovered_output:
                raise AIValidationError(
                    "Nemotron recovery request "
                    "returned only thinking content."
                )

            logger.debug(
                "Nemotron recovery response received: "
                "length=%d",
                len(recovered_output),
            )

            return self._validate_structured_response(
                recovered_output,
                target_schema,
            )

        except Exception as recovery_error:
            logger.warning(
                "Nemotron structured JSON recovery failed: %s",
                str(recovery_error),
            )

            logger.debug(
                "Nemotron recovery response preview: %s",
                self._safe_response_preview(
                    recovered_output
                ),
            )

            raise AIValidationError(
                "Nemotron returned malformed "
                "structured output after recovery."
            ) from recovery_error

    # ==================================================================
    # Device risk analysis
    # ==================================================================

    async def analyze_device_risk(
        self,
        device_data: Dict[str, Any],
        deterministic_score: float,
        score_breakdown: Dict[str, Any],
    ) -> DeviceRiskExplanation:
        """Provide contextual narrative explaining device risk."""

        sanitized = sanitize_device_data(
            device_data
        )

        if not self.is_configured:
            return self._fallback_device_risk(
                sanitized,
                deterministic_score,
                score_breakdown,
            )

        prompt = build_device_risk_prompt(
            sanitized,
            deterministic_score,
            score_breakdown,
        )

        try:
            return await self._call_structured_model(
                SYSTEM_PROMPT_SECURITY_ANALYST,
                prompt,
                DeviceRiskExplanation,
            )

        except Exception as exc:
            logger.warning(
                "Nemotron device risk fallback: %s",
                str(exc),
            )

            return self._fallback_device_risk(
                sanitized,
                deterministic_score,
                score_breakdown,
            )

    # ==================================================================
    # Security finding explanation
    # ==================================================================

    async def explain_security_finding(
        self,
        finding_data: Dict[str, Any],
        device_context: Dict[str, Any],
    ) -> FindingExplanation:
        """Explain a security posture finding."""

        sanitized_finding = (
            sanitize_device_data(
                finding_data
            )
        )

        sanitized_device = (
            sanitize_device_data(
                device_context
            )
        )

        if not self.is_configured:
            return self._fallback_finding_explanation(
                sanitized_finding,
                sanitized_device,
            )

        prompt = build_finding_explanation_prompt(
            sanitized_finding,
            sanitized_device,
        )

        try:
            return await self._call_structured_model(
                SYSTEM_PROMPT_SECURITY_ANALYST,
                prompt,
                FindingExplanation,
            )

        except Exception as exc:
            logger.warning(
                "Nemotron finding explanation fallback: %s",
                str(exc),
            )

            return self._fallback_finding_explanation(
                sanitized_finding,
                sanitized_device,
            )

    # ==================================================================
    # Telemetry explanation
    # ==================================================================

    async def explain_telemetry_event(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Dict[str, Any],
    ) -> TelemetryExplanation:
        """Triage network telemetry."""

        sanitized_event = (
            sanitize_device_data(
                event_data
            )
        )

        sanitized_anomaly = (
            sanitize_device_data(
                anomaly_data
            )
        )

        if not self.is_configured:
            return self._fallback_telemetry_explanation(
                sanitized_event,
                sanitized_anomaly,
            )

        prompt = build_telemetry_triage_prompt(
            sanitized_event,
            sanitized_anomaly,
        )

        try:
            return await self._call_structured_model(
                SYSTEM_PROMPT_SECURITY_ANALYST,
                prompt,
                TelemetryExplanation,
            )

        except Exception as exc:
            logger.warning(
                "Nemotron telemetry fallback: %s",
                str(exc),
            )

            return self._fallback_telemetry_explanation(
                sanitized_event,
                sanitized_anomaly,
            )

    # ==================================================================
    # Honeypot analysis
    # ==================================================================

    async def explain_honeypot_event(
        self,
        event_data: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
    ) -> HoneypotAnalysisResponse:
        """Analyze honeypot telemetry using Nemotron."""

        sanitized_event = (
            sanitize_device_data(
                event_data
            )
        )

        sanitized_recent = [
            sanitize_device_data(event)
            for event in recent_events
        ]

        if not self.is_configured:
            return self._fallback_honeypot_explanation(
                sanitized_event,
                sanitized_recent,
            )

        prompt = build_honeypot_analysis_prompt(
            sanitized_event,
            sanitized_recent,
        )

        try:
            return await self._call_structured_model(
                SYSTEM_PROMPT_SECURITY_ANALYST,
                prompt,
                HoneypotAnalysisResponse,
            )

        except Exception as exc:
            logger.warning(
                "Nemotron honeypot fallback: %s",
                str(exc),
            )

            return self._fallback_honeypot_explanation(
                sanitized_event,
                sanitized_recent,
            )

    # ==================================================================
    # Hardening guide
    # ==================================================================

    async def generate_hardening_guide(
        self,
        target_type: str,
        observed_services: List[int],
        context: Dict[str, Any],
    ) -> HardeningGuideResponse:
        """Generate safe defensive hardening recommendations."""

        sanitized_context = (
            sanitize_device_data(
                context
            )
        )

        if not self.is_configured:
            return self._fallback_hardening_guide(
                target_type,
                observed_services,
                sanitized_context,
            )

        prompt = build_hardening_guide_prompt(
            target_type,
            observed_services,
            sanitized_context,
        )

        try:
            return await self._call_structured_model(
                SYSTEM_PROMPT_SECURITY_ANALYST,
                prompt,
                HardeningGuideResponse,
            )

        except Exception as exc:
            logger.warning(
                "Nemotron hardening guide fallback: %s",
                str(exc),
            )

            return self._fallback_hardening_guide(
                target_type,
                observed_services,
                sanitized_context,
            )

    # ==================================================================
    # Security event triage
    # ==================================================================

    async def triage_security_event(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Optional[
            Dict[str, Any]
        ] = None,
    ) -> AIThreatAnalysis:
        """Perform structured defensive security-event triage."""

        sanitized_event = (
            sanitize_device_data(
                event_data
            )
        )

        sanitized_anomaly = (
            sanitize_device_data(
                anomaly_data or {}
            )
        )

        if not self.is_configured:
            return self._fallback_threat_analysis(
                sanitized_event,
                sanitized_anomaly,
            )

        prompt = build_telemetry_triage_prompt(
            sanitized_event,
            sanitized_anomaly,
        )

        try:
            return await self._call_structured_model(
                SYSTEM_PROMPT_SECURITY_ANALYST,
                prompt,
                AIThreatAnalysis,
            )

        except Exception as exc:
            logger.warning(
                "Nemotron threat analysis fallback: %s",
                str(exc),
            )

            return self._fallback_threat_analysis(
                sanitized_event,
                sanitized_anomaly,
            )

    # ==================================================================
    # Conversational AI advisor
    # ==================================================================

    async def chat_advisory(
        self,
        message: str,
        history: Optional[
            List[Dict[str, str]]
        ] = None,
        context: Optional[
            Dict[str, Any]
        ] = None,
    ) -> AIChatResponse:
        """
        Interactive defensive cybersecurity advisory chat.
        """

        clean_message = sanitize_text(
            message
        )

        if not clean_message:
            return AIChatResponse(
                reply=(
                    "Please provide a security "
                    "question or observation."
                ),
                suggested_followups=[
                    "Explain my device risk score",
                    "How should I review open ports?",
                    "How can I harden my home network?",
                ],
                ai_available=self.is_configured,
                model_name=self.model,
            )

        if not self.is_configured:
            return AIChatResponse(
                reply=(
                    "NVIDIA Nemotron AI Security "
                    "Advisor is currently running in "
                    "offline deterministic mode. "
                    "Local device risk assessments "
                    "and security posture findings "
                    "remain available through the "
                    "deterministic Risk Engine. "
                    "Configure NVIDIA credentials to "
                    "activate conversational AI advisory."
                ),
                suggested_followups=[
                    "How is my device risk score calculated?",
                    "What ports are open on my network?",
                    "How do I harden exposed SMB or HTTP services?",
                ],
                ai_available=False,
                model_name=self.model,
            )

        client = self._get_client()

        messages: List[
            Dict[str, str]
        ] = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT_CHAT,
            }
        ]

        # --------------------------------------------------------------
        # Conversation history
        # --------------------------------------------------------------

        if history:
            for turn in history[-6:]:
                role = turn.get(
                    "role",
                    "user",
                )

                content = sanitize_text(
                    turn.get(
                        "content",
                        "",
                    )
                )

                if (
                    role in (
                        "user",
                        "assistant",
                    )
                    and content
                ):
                    messages.append(
                        {
                            "role": role,
                            "content": content,
                        }
                    )

        # --------------------------------------------------------------
        # Security context
        # --------------------------------------------------------------

        user_content = clean_message

        if context:
            sanitized_context = (
                sanitize_device_data(
                    context
                )
            )

            user_content = (
                f"{clean_message}\n\n"
                "[Attached Security Context]\n"
                f"{sanitized_context}"
            )

        messages.append(
            {
                "role": "user",
                "content": user_content,
            }
        )

        # --------------------------------------------------------------
        # Model request
        # --------------------------------------------------------------

        try:
            response = (
                await client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.3,
                    max_tokens=MAX_OUTPUT_TOKENS,
                    extra_body=self._thinking_options(),
                )
            )

            if not response.choices:
                raise AIValidationError(
                    "NVIDIA Nemotron returned no choices."
                )

            message_obj = (
                response.choices[0].message
            )

            if message_obj is None:
                raise AIValidationError(
                    "NVIDIA Nemotron returned "
                    "an empty message."
                )

            raw_reply = (
                self._message_content_to_text(
                    getattr(
                        message_obj,
                        "content",
                        None,
                    )
                )
            )

            raw_reply = (
                self._remove_thinking_blocks(
                    raw_reply
                )
            )

            reply = sanitize_ai_reply(
                raw_reply
            )

            if not reply:
                reply = (
                    "Nemotron returned an empty "
                    "advisory response. Please try "
                    "the question again."
                )

            return AIChatResponse(
                reply=reply,
                suggested_followups=[
                    "Review recommended remediation steps",
                    "How can I verify the change?",
                    "Check network anomaly indicators",
                ],
                ai_available=True,
                model_name=self.model,
            )

        except openai.APITimeoutError:
            logger.warning(
                "Nemotron chat request timed out."
            )

        except openai.RateLimitError:
            logger.warning(
                "Nemotron chat rate limit exceeded."
            )

        except openai.APIStatusError as exc:
            logger.warning(
                "Nemotron chat API status %s.",
                exc.status_code,
            )

        except openai.APIConnectionError:
            logger.warning(
                "Nemotron chat connection failed."
            )

        except Exception as exc:
            logger.warning(
                "Nemotron chat fallback triggered: %s",
                str(exc),
            )

        return AIChatResponse(
            reply=(
                "NVIDIA Nemotron AI Advisor is "
                "temporarily unreachable. "
                "Deterministic defensive risk "
                "analysis remains active."
            ),
            suggested_followups=[
                "Check deterministic risk posture",
                "Review exposed services",
            ],
            ai_available=False,
            model_name=self.model,
        )

    # ==================================================================
    # Deterministic fallback generators
    # ==================================================================

    def _fallback_device_risk(
        self,
        device_data: Dict[str, Any],
        score: float,
        score_breakdown: Dict[str, Any],
    ) -> DeviceRiskExplanation:
        """Deterministic fallback device risk narrative."""

        ports = device_data.get(
            "ports",
            [],
        )

        return DeviceRiskExplanation(
            device_id=str(
                device_data.get(
                    "id",
                    "unknown",
                )
            ),
            deterministic_risk_score=score,
            key_observations=[
                (
                    "Device Type: "
                    f"{device_data.get('device_type', 'UNKNOWN')}"
                ),
                f"Active observed ports: {len(ports)}",
            ],
            risk_factors_explained=[
                (
                    "Deterministic Risk Score calculated "
                    f"at {score}/100 based on exposure "
                    "and finding severity."
                )
            ],
            likely_security_implications=(
                "Device exposure is evaluated using "
                "deterministic port weights and verified "
                "security findings."
            ),
            defensive_priorities=[
                "Review open administrative or unencrypted ports.",
                "Ensure device firmware is current.",
                "Isolate sensitive IoT devices on a guest or IoT VLAN.",
            ],
            ai_available=False,
        )

    def _fallback_finding_explanation(
        self,
        finding_data: Dict[str, Any],
        device_context: Dict[str, Any],
    ) -> FindingExplanation:
        """Deterministic fallback finding explanation."""

        title = finding_data.get(
            "title",
            "Security Posture Finding",
        )

        sev_str = str(
            finding_data.get(
                "severity",
                "MEDIUM",
            )
        ).upper()

        try:
            severity = Severity(
                sev_str
            )
        except ValueError:
            severity = Severity.MEDIUM

        return FindingExplanation(
            title=title,
            severity=severity,
            explanation=finding_data.get(
                "description",
                "Deterministic security posture observation.",
            ),
            potential_impact=(
                "Exposed unencrypted or administrative "
                "services increase the local network "
                "attack surface."
            ),
            observed_facts=[
                f"Finding: {title}",
                f"Severity: {severity.value}",
            ],
            inferred_risks=[
                "Potential lateral movement vector if "
                "the device is compromised on the local subnet."
            ],
            defensive_recommendations=[
                "Restrict access to trusted local "
                "management IPs only."
            ],
            remediation_steps=finding_data.get(
                "remediation_steps",
                [
                    "Review service configuration."
                ],
            ),
            cve_context=(
                "No confirmed CVE exploitation observed "
                "in supplied telemetry."
            ),
            ai_available=False,
        )

    def _fallback_telemetry_explanation(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Dict[str, Any],
    ) -> TelemetryExplanation:
        """Deterministic fallback telemetry explanation."""

        is_anomalous = (
            anomaly_data.get("status")
            in (
                "anomalous",
                "severe_anomaly",
                "elevated",
            )
        )

        return TelemetryExplanation(
            event_classification="TELEMETRY_EVENT",
            is_anomaly=is_anomalous,
            confidence=0.75,
            observed_facts=[
                (
                    "Protocol: "
                    f"{event_data.get('protocol', 'TCP')}"
                ),
                (
                    "Port: "
                    f"{event_data.get('destination_port', 0)}"
                ),
            ],
            inferred_risks=[
                "Baseline telemetry evaluated deterministically."
            ],
            explanation=(
                "Deterministic telemetry analysis processed "
                "without external AI commentary."
            ),
            recommended_action=(
                "Monitor event frequency and verify "
                "destination endpoint authorization."
            ),
            ai_available=False,
        )

    def _fallback_honeypot_explanation(
        self,
        event_data: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
    ) -> HoneypotAnalysisResponse:
        """Deterministic fallback honeypot explanation."""

        raw_id = event_data.get(
            "id"
        )

        try:
            event_uuid = (
                uuid.UUID(
                    str(raw_id)
                )
                if raw_id
                else uuid.uuid4()
            )

        except (
            ValueError,
            TypeError,
            AttributeError,
        ):
            event_uuid = uuid.uuid4()

        interaction_type = event_data.get(
            "interaction_type",
            "http_request",
        )

        honeypot_id = event_data.get(
            "honeypot_id",
            "iot_gateway",
        )

        source_ip = event_data.get(
            "source_ip",
            "unknown",
        )

        severity_value = event_data.get(
            "severity",
            Severity.LOW,
        )

        if isinstance(
            severity_value,
            str,
        ):
            try:
                severity = Severity(
                    severity_value
                )
            except ValueError:
                severity = Severity.LOW
        else:
            severity = (
                severity_value
                or Severity.LOW
            )

        # --------------------------------------------------------------
        # Login/authentication probe
        # --------------------------------------------------------------

        if interaction_type in (
            "login_attempt",
            "auth_attempt",
        ):
            summary = (
                "Authentication interaction recorded "
                f"by decoy {honeypot_id} from "
                f"{source_ip}."
            )

            pattern = (
                "Credential-Probing / "
                "Login Endpoint Interaction"
            )

            implications = [
                (
                    "A host interacted with the decoy "
                    "authentication endpoint."
                ),
                (
                    "The supplied telemetry does not "
                    "establish successful authentication "
                    "or compromise."
                ),
            ]

            actions = [
                (
                    "Verify the owner and running processes "
                    f"of source IP {source_ip}."
                ),
                (
                    "Review authentication logs for "
                    "repeated attempts from the same source."
                ),
                (
                    "Ensure strong unique passwords are "
                    "used on genuine IoT devices."
                ),
            ]

        # --------------------------------------------------------------
        # Administrative endpoint
        # --------------------------------------------------------------

        elif interaction_type in (
            "admin_endpoint_access",
            "suspicious_request",
        ):
            summary = (
                "Administrative endpoint/configuration "
                f"probe recorded by decoy "
                f"{honeypot_id} from {source_ip}."
            )

            pattern = (
                "Administrative Endpoint "
                "Probing / Discovery"
            )

            implications = [
                (
                    "The source interacted with an "
                    "administrative or suspicious endpoint."
                ),
                (
                    "The supplied telemetry does not "
                    "establish successful exploitation."
                ),
            ]

            actions = [
                (
                    "Inspect the device at the source IP "
                    "for unauthorized automated activity."
                ),
                (
                    "Review firewall rules to ensure "
                    "administrative interfaces are not "
                    "reachable from guest networks."
                ),
            ]

        # --------------------------------------------------------------
        # SSH
        # --------------------------------------------------------------

        elif interaction_type == "ssh_connection":
            destination_port = event_data.get(
                "destination_port",
                2222,
            )

            summary = (
                "SSH interaction recorded by simulated "
                f"SSH decoy service on port "
                f"{destination_port}."
            )

            pattern = (
                "SSH Service Interaction / "
                "Potential Reconnaissance"
            )

            implications = [
                (
                    "A source interacted with the "
                    "simulated SSH service."
                ),
                (
                    "The supplied telemetry does not "
                    "establish successful authentication "
                    "or shell execution."
                ),
            ]

            actions = [
                (
                    "Verify whether SSH is required "
                    "on the corresponding genuine device."
                ),
                (
                    "Disable unnecessary SSH exposure."
                ),
                (
                    "Use key-based authentication where "
                    "SSH administration is required."
                ),
            ]

        # --------------------------------------------------------------
        # Generic interaction
        # --------------------------------------------------------------

        else:
            summary = (
                f"Deception trap {honeypot_id} "
                f"recorded a {interaction_type} "
                f"interaction from {source_ip}."
            )

            pattern = (
                "Decoy Service Interaction"
            )

            implications = [
                (
                    "The interaction was captured "
                    "as isolated honeypot telemetry."
                ),
            ]

            actions = [
                (
                    "Monitor for repeated interactions "
                    "from the same source."
                ),
            ]

        return HoneypotAnalysisResponse(
            event_id=event_uuid,
            summary=summary,
            pattern_detected=pattern,
            severity=severity,
            defensive_implications=implications,
            recommended_actions=actions,
            confidence=0.85,
            model_used=(
                "NVIDIA Nemotron "
                "(Deterministic Fallback)"
            ),
        )

    def _fallback_hardening_guide(
        self,
        target_type: str,
        observed_services: List[int],
        context: Dict[str, Any],
    ) -> HardeningGuideResponse:
        """Deterministic fallback hardening guide."""

        items: List[
            HardeningItem
        ] = []

        # --------------------------------------------------------------
        # HTTP
        # --------------------------------------------------------------

        if 80 in observed_services:
            items.append(
                HardeningItem(
                    priority="HIGH",
                    action=(
                        "Enforce HTTPS or disable "
                        "plaintext HTTP administration"
                    ),
                    reason=(
                        "Plaintext HTTP can transmit "
                        "credentials without transport encryption."
                    ),
                    safe_steps=[
                        "Log in to the device web interface.",
                        "Enable HTTPS/TLS where supported.",
                        "Disable port 80 if it is not required.",
                    ],
                    verification_guidance=(
                        "Verify management access uses HTTPS "
                        "and unnecessary port 80 exposure is removed."
                    ),
                )
            )

        # --------------------------------------------------------------
        # SMB
        # --------------------------------------------------------------

        if 445 in observed_services:
            items.append(
                HardeningItem(
                    priority="HIGH",
                    action=(
                        "Restrict or disable SMB file sharing "
                        "across untrusted network segments"
                    ),
                    reason=(
                        "SMB services can increase lateral "
                        "movement risk when unnecessarily exposed."
                    ),
                    safe_steps=[
                        "Disable SMBv1 entirely.",
                        (
                            "Require SMB signing and encryption "
                            "where supported."
                        ),
                        (
                            "Restrict SMB access to trusted "
                            "network segments."
                        ),
                    ],
                    verification_guidance=(
                        "Ensure only authorized authenticated "
                        "hosts can reach the SMB service."
                    ),
                )
            )

        # --------------------------------------------------------------
        # Generic baseline
        # --------------------------------------------------------------

        if not items:
            items.append(
                HardeningItem(
                    priority="MEDIUM",
                    action=(
                        "Review network segmentation "
                        "and firmware updates"
                    ),
                    reason=(
                        "Network segmentation and current "
                        "firmware provide a strong defensive baseline."
                    ),
                    safe_steps=[
                        (
                            "Check the vendor support page "
                            "for firmware patches."
                        ),
                        (
                            "Place IoT devices on an "
                            "isolated network."
                        ),
                    ],
                    verification_guidance=(
                        "Confirm devices are running supported "
                        "and current firmware."
                    ),
                )
            )

        return HardeningGuideResponse(
            target_type=target_type,
            hardening_items=items,
            summary=(
                f"Defensive hardening guide for "
                f"{target_type} with "
                f"{len(observed_services)} "
                "observed services."
            ),
            ai_available=False,
        )

    def _fallback_threat_analysis(
        self,
        event_data: Dict[str, Any],
        anomaly_data: Dict[str, Any],
    ) -> AIThreatAnalysis:
        """Deterministic fallback threat analysis."""

        try:
            score = float(
                anomaly_data.get(
                    "anomaly_score",
                    0.0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            score = 0.0

        is_threat = score >= 50.0

        if score >= 80.0:
            severity = Severity.HIGH

        elif is_threat:
            severity = Severity.MEDIUM

        else:
            severity = Severity.LOW

        return AIThreatAnalysis(
            threat_detected=is_threat,
            threat_type=(
                "ELEVATED_TELEMETRY"
                if is_threat
                else "NORMAL_ACTIVITY"
            ),
            severity=severity,
            confidence=0.70,
            reason=(
                f"Deterministic baseline score: "
                f"{score}/100. "
                "AI advisor running in offline "
                "fallback mode."
            ),
            recommended_action=(
                "Inspect source and destination "
                "endpoints for anomalous connection "
                "patterns."
                if is_threat
                else "No immediate action required."
            ),
            evidence=[
                f"Anomaly score: {score}",
                (
                    "Baseline status: "
                    f"{anomaly_data.get('status', 'normal')}"
                ),
            ],
            recommendations=[
                "Verify device IP authorization.",
                "Review port communications.",
            ],
        )