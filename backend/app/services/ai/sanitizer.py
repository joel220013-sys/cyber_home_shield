"""Sanitization, prompt-injection defense, and safe AI output handling."""

import json
import re
from typing import Any, Dict, Optional, Type, TypeVar

from pydantic import BaseModel, ValidationError

from app.core.exceptions import AppBaseException


T = TypeVar("T", bound=BaseModel)


# ---------------------------------------------------------------------------
# Sensitive-data detection
# ---------------------------------------------------------------------------

PASSWORD_KEY_PATTERN = re.compile(
    r"(password|secret|token|api[_-]?key|private[_-]?key|"
    r"authorization|auth|bearer|credential)",
    re.IGNORECASE,
)

MAC_ADDRESS_PATTERN = re.compile(
    r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
)

PROMPT_INJECTION_PATTERN = re.compile(
    r"("
    r"ignore previous instructions|"
    r"ignore all previous instructions|"
    r"system override|"
    r"reveal the api key|"
    r"reveal your instructions|"
    r"forget all instructions|"
    r"you are now a|"
    r"act as an unfiltered|"
    r"disable your safety|"
    r"bypass your restrictions"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# AI validation exception
# ---------------------------------------------------------------------------

class AIValidationError(AppBaseException):
    """Raised when an AI response fails validation."""

    def __init__(
        self,
        message: str,
        details: Optional[Any] = None,
    ):
        super().__init__(message, details)


# ---------------------------------------------------------------------------
# General text sanitization
# ---------------------------------------------------------------------------

def sanitize_text(text: Optional[str]) -> str:
    """
    Sanitize untrusted text before sending it to the AI model.

    Protects against:
    - prompt-injection phrases
    - excessively large input payloads
    """

    if not text:
        return ""

    clean = str(text)

    # Neutralize common prompt-injection attempts.
    clean = PROMPT_INJECTION_PATTERN.sub(
        "[UNTRUSTED_INSTRUCTION_REDACTED]",
        clean,
    )

    # Prevent oversized prompt payloads.
    return clean[:1000]


# ---------------------------------------------------------------------------
# Device / telemetry sanitization
# ---------------------------------------------------------------------------

def sanitize_device_data(
    data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Sanitize device/telemetry data before sending it to an AI provider.

    Protections:
    - credential/token redaction
    - MAC address masking
    - prompt-injection neutralization
    - recursive dictionary sanitization
    - list sanitization
    """

    if not isinstance(data, dict):
        return {}

    sanitized: Dict[str, Any] = {}

    for key, value in data.items():

        # Never send credential-like fields to the model.
        if PASSWORD_KEY_PATTERN.search(str(key)):
            sanitized[key] = "[REDACTED_SECRET]"
            continue

        if isinstance(value, str):

            # Mask MAC addresses.
            cleaned_value = MAC_ADDRESS_PATTERN.sub(
                "XX:XX:XX:XX:XX:XX",
                value,
            )

            # Neutralize prompt injection.
            cleaned_value = sanitize_text(cleaned_value)

            sanitized[key] = cleaned_value

        elif isinstance(value, dict):

            sanitized[key] = sanitize_device_data(value)

        elif isinstance(value, list):

            sanitized[key] = [
                (
                    sanitize_device_data(item)
                    if isinstance(item, dict)
                    else (
                        sanitize_text(item)
                        if isinstance(item, str)
                        else item
                    )
                )
                for item in value
            ]

        else:
            sanitized[key] = value

    return sanitized


# ---------------------------------------------------------------------------
# AI conversational output sanitization
# ---------------------------------------------------------------------------

def sanitize_ai_reply(
    raw_text: Optional[str],
) -> str:
    """
    Sanitize conversational AI output before returning it to the frontend.

    Removes:
    - <think>...</think> reasoning blocks
    - common visible reasoning headers
    - accidental chain-of-thought wrappers

    This function does NOT attempt to rewrite the model's answer.
    It only removes explicit reasoning leakage and limits output size.
    """

    if not raw_text:
        return ""

    clean = str(raw_text)

    # Remove explicit reasoning blocks.
    clean = re.sub(
        r"<think>.*?</think>",
        "",
        clean,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Remove common reasoning introduction.
    clean = re.sub(
        r"^\s*(here(?:'s| is)\s+(?:a\s+)?thinking\s+process)\s*:?\s*",
        "",
        clean,
        flags=re.IGNORECASE,
    )

    # Remove common visible reasoning headers.
    clean = re.sub(
        r"^\s*(analysis|reasoning|chain\s+of\s+thought)\s*:\s*",
        "",
        clean,
        flags=re.IGNORECASE,
    )

    # Remove a leading "mental process" section if explicitly marked.
    clean = re.sub(
        r"^\s*(?:internal\s+reasoning|internal\s+analysis)\s*:?\s*",
        "",
        clean,
        flags=re.IGNORECASE,
    )

    # Normalize excessive blank lines.
    clean = re.sub(
        r"\n{3,}",
        "\n\n",
        clean,
    )

    # Protect the API/frontend from unexpectedly huge responses.
    clean = clean.strip()[:8000]

    return clean


# ---------------------------------------------------------------------------
# Safe JSON extraction and Pydantic validation
# ---------------------------------------------------------------------------

def extract_and_validate_json(
    raw_text: str,
    target_schema: Type[T],
) -> T:
    """
    Safely extract and validate JSON from model output.

    Handles:
    - <think>...</think> blocks
    - Markdown ```json blocks
    - surrounding natural-language text
    - Pydantic schema validation

    The final returned object is always validated against the
    supplied Pydantic schema.
    """

    if not raw_text or not raw_text.strip():
        raise AIValidationError(
            "Received empty response from AI model."
        )

    # ---------------------------------------------------------------
    # 1. Remove explicit reasoning blocks.
    # ---------------------------------------------------------------

    cleaned = re.sub(
        r"<think>.*?</think>",
        "",
        raw_text,
        flags=re.DOTALL | re.IGNORECASE,
    ).strip()

    # ---------------------------------------------------------------
    # 2. Remove common reasoning prefix if present.
    # ---------------------------------------------------------------

    cleaned = re.sub(
        r"^\s*(here(?:'s| is)\s+(?:a\s+)?thinking\s+process)\s*:?\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    # ---------------------------------------------------------------
    # 3. Extract JSON from Markdown code block.
    # ---------------------------------------------------------------

    json_code_match = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        cleaned,
        flags=re.DOTALL | re.IGNORECASE,
    )

    if json_code_match:
        candidate_json = json_code_match.group(1).strip()

    else:
        # -----------------------------------------------------------
        # 4. Locate the outermost JSON object.
        # -----------------------------------------------------------

        start_index = cleaned.find("{")
        end_index = cleaned.rfind("}")

        if (
            start_index != -1
            and end_index != -1
            and end_index > start_index
        ):
            candidate_json = cleaned[
                start_index:end_index + 1
            ].strip()
        else:
            candidate_json = cleaned

    # ---------------------------------------------------------------
    # 5. Parse JSON.
    # ---------------------------------------------------------------

    try:
        parsed_data = json.loads(candidate_json)

    except json.JSONDecodeError as exc:
        raise AIValidationError(
            f"Malformed JSON in AI response: {exc}"
        ) from exc

    # ---------------------------------------------------------------
    # 6. Ensure JSON object.
    # ---------------------------------------------------------------

    if not isinstance(parsed_data, dict):
        raise AIValidationError(
            "Expected JSON object, "
            f"got {type(parsed_data).__name__}"
        )

    # ---------------------------------------------------------------
    # 7. Validate against Pydantic schema.
    # ---------------------------------------------------------------

    try:
        return target_schema.model_validate(parsed_data)

    except ValidationError as exc:
        raise AIValidationError(
            f"AI response failed schema validation: {exc}"
        ) from exc
