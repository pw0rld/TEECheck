"""LLM response parser with retry logic."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from tee_audit.llm.client import LLMClient

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

MAX_RETRIES = 3


class LLMParsingError(Exception):
    """Raised when LLM response cannot be parsed after retries."""

    def __init__(self, message: str, raw_response: str, stage: str = "") -> None:
        super().__init__(message)
        self.raw_response = raw_response
        self.stage = stage


def parse_with_retry(
    client: LLMClient,
    system: str,
    user: str,
    schema: type[T],
    max_retries: int = MAX_RETRIES,
    error_save_dir: Path | None = None,
    temperature: float = 0.0,
) -> T:
    """Attempt structured LLM completion with retry on parse failure.

    Uses the client's complete_structured() for initial attempt.
    On failure, retries with schema error feedback.
    On persistent failure, saves raw response and raises LLMParsingError.
    """
    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            result = client.complete_structured(system, user, schema, temperature=temperature)
            if attempt > 0:
                logger.info("Parse succeeded on attempt %d", attempt + 1)
            return result
        except (ValidationError, json.JSONDecodeError, ValueError, TypeError) as e:
            last_error = e
            logger.warning("Parse attempt %d/%d failed: %s", attempt + 1, max_retries, str(e)[:200])

            if attempt < max_retries - 1:
                # Add schema feedback to the prompt for retry
                schema_str = json.dumps(schema.model_json_schema(), indent=2)
                user = (
                    f"{user}\n\n"
                    f"Your previous response failed validation: {str(e)[:500]}\n"
                    f"Required schema:\n```json\n{schema_str}\n```\n"
                    f"Please respond with valid JSON matching this schema."
                )

    # All retries exhausted
    raw_response = ""
    try:
        raw_response = client.complete(system, user, temperature=0)  # Fallback uses temp=0 for deterministic diagnostics
    except Exception as e:
        logger.debug("Fallback raw completion also failed: %s", str(e)[:200])

    if error_save_dir:
        error_save_dir.mkdir(parents=True, exist_ok=True)
        error_file = error_save_dir / f"parse_error_{schema.__name__}.json"
        error_file.write_text(json.dumps({
            "error": str(last_error),
            "raw_response": raw_response[:10000],
            "schema": schema.__name__,
        }, indent=2, default=str))
        logger.error("Parse error saved to %s", error_file)

    raise LLMParsingError(
        f"Failed to parse LLM response as {schema.__name__} after {max_retries} attempts: {last_error}",
        raw_response=raw_response,
        stage=schema.__name__,
    )
