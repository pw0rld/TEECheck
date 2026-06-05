"""LLM client abstraction — Anthropic, OpenAI, GLM, and Codex with structured output support."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_DEFAULT_MAX_RETRIES = 5
_DEFAULT_BASE_DELAY = 10


class LLMClient(ABC):
    """Abstract LLM client with basic and structured completion support."""

    def __init__(self, api_key: str, model: str = "") -> None:
        self.api_key = api_key
        self.model = model
        self.total_tokens_used = 0
        self._tokens_lock = threading.Lock()

    def _add_tokens(self, count: int) -> None:
        """Thread-safe token counter increment."""
        with self._tokens_lock:
            self.total_tokens_used += count

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        """Check if an exception is a rate-limit (429) error."""
        msg = str(exc).lower()
        if "429" in msg or "rate limit" in msg or "too many requests" in msg:
            return True
        status = getattr(exc, "status_code", None) or getattr(
            getattr(exc, "response", None), "status_code", None
        )
        return status == 429

    def _retry_with_backoff(self, fn, max_retries: int = _DEFAULT_MAX_RETRIES):
        """Call fn() with exponential backoff on rate-limit errors."""
        for attempt in range(max_retries + 1):
            try:
                return fn()
            except Exception as exc:
                if not self._is_rate_limit_error(exc) or attempt == max_retries:
                    raise
                delay = _DEFAULT_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Rate limited (429), retrying in %ds (attempt %d/%d)",
                    delay, attempt + 1, max_retries,
                )
                time.sleep(delay)

    @abstractmethod
    def complete(self, system: str, user: str, temperature: float = 0) -> str:
        """Basic text completion."""

    @abstractmethod
    def complete_structured(
        self, system: str, user: str, schema: type[T], temperature: float = 0
    ) -> T:
        """Structured JSON completion using tool use / function calling.

        Returns a validated pydantic model instance.
        """

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """Estimate token count for cost tracking."""


class AnthropicClient(LLMClient):
    """Anthropic API client using tool use for structured output."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514") -> None:
        super().__init__(api_key, model)
        self._client = None
        self._init_lock = threading.Lock()

    def _get_client(self):
        """Lazy-init Anthropic client for connection reuse (thread-safe)."""
        if self._client is None:
            with self._init_lock:
                if self._client is None:
                    import anthropic
                    self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def complete(self, system: str, user: str, temperature: float = 0) -> str:
        def _call():
            client = self._get_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                temperature=temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            self._add_tokens(
                getattr(response.usage, "input_tokens", 0)
                + getattr(response.usage, "output_tokens", 0)
            )
            return response.content[0].text
        return self._retry_with_backoff(_call)

    def complete_structured(
        self, system: str, user: str, schema: type[T], temperature: float = 0
    ) -> T:
        """Use Anthropic tool use to get structured JSON output."""
        def _call():
            client = self._get_client()

            # Build a tool that matches the pydantic schema
            json_schema = schema.model_json_schema()
            tool_name = schema.__name__
            tool_def = {
                "name": tool_name,
                "description": f"Respond with a structured {tool_name} object.",
                "input_schema": json_schema,
            }

            response = client.messages.create(
                model=self.model,
                max_tokens=8192,
                temperature=temperature,
                system=system,
                tools=[{"type": "custom", "custom": tool_def}],
                messages=[{"role": "user", "content": user}],
            )

            self._add_tokens(
                getattr(response.usage, "input_tokens", 0)
                + getattr(response.usage, "output_tokens", 0)
            )

            # Extract tool use block
            for block in response.content:
                if block.type == "tool_use":
                    return schema.model_validate(block.input)

            # Fallback: try to parse text as JSON
            text = "".join(b.text for b in response.content if hasattr(b, "text"))
            return schema.model_validate_json(text)
        return self._retry_with_backoff(_call)

    def count_tokens(self, text: str) -> int:
        # Rough estimate: ~4 chars per token
        return len(text) // 4


class OpenAIClient(LLMClient):
    """OpenAI API client using function calling for structured output."""

    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = "") -> None:
        super().__init__(api_key, model)
        self._base_url = base_url
        self._client = None
        self._init_lock = threading.Lock()

    def _get_client(self):
        """Lazy-init OpenAI client for connection reuse (thread-safe)."""
        if self._client is None:
            with self._init_lock:
                if self._client is None:
                    from openai import OpenAI
                    kwargs: dict = {"api_key": self.api_key, "timeout": 300}
                    if self._base_url:
                        kwargs["base_url"] = self._base_url
                    self._client = OpenAI(**kwargs)
        return self._client

    def complete(self, system: str, user: str, temperature: float = 0) -> str:
        def _call():
            client = self._get_client()
            response = client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            usage = response.usage
            if usage:
                self._add_tokens(usage.total_tokens)
            return response.choices[0].message.content or ""
        return self._retry_with_backoff(_call)

    def complete_structured(
        self, system: str, user: str, schema: type[T], temperature: float = 0
    ) -> T:
        """Use OpenAI function calling to get structured JSON output."""
        def _call():
            client = self._get_client()
            json_schema = schema.model_json_schema()

            response = client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                tools=[{
                    "type": "function",
                    "function": {
                        "name": schema.__name__,
                        "description": f"Respond with a structured {schema.__name__} object.",
                        "parameters": json_schema,
                    }
                }],
                tool_choice={"type": "function", "function": {"name": schema.__name__}},
            )

            usage = response.usage
            if usage:
                self._add_tokens(usage.total_tokens)

            msg = response.choices[0].message
            if msg.tool_calls:
                func_call = msg.tool_calls[0]
                return schema.model_validate_json(func_call.function.arguments)

            # Fallback: legacy function_call or text
            if hasattr(msg, "function_call") and msg.function_call and msg.function_call.arguments:
                return schema.model_validate_json(msg.function_call.arguments)

            text = msg.content or "{}"
            return schema.model_validate_json(text)
        return self._retry_with_backoff(_call)

    def count_tokens(self, text: str) -> int:
        return len(text) // 4


class GLMClient(OpenAIClient):
    """GLM (zhipuai) API client -- OpenAI-compatible endpoint."""

    def __init__(self, api_key: str, model: str = "glm-5.1", base_url: str = "") -> None:
        resolved_url = base_url or os.environ.get(
            "GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"
        )
        super().__init__(api_key, model, base_url=resolved_url)

    def complete_structured(
        self, system: str, user: str, schema: type[T], temperature: float = 0
    ) -> T:
        """GLM doesn't reliably support tool use. Prompt for JSON directly."""
        import json as _json

        json_schema = schema.model_json_schema()
        json_instruction = (
            f"\n\nRespond with ONLY valid JSON matching this schema (no markdown, no code fences):\n"
            f"```json\n{_json.dumps(json_schema, indent=2)}\n```"
        )

        def _call():
            response_text = self.complete(system, user + json_instruction, temperature=temperature)
            # Strip markdown code fences if present
            text = response_text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
            text = text.strip()
            return schema.model_validate_json(text)

        return self._retry_with_backoff(_call)


class CodexClient(OpenAIClient):
    """Codex API client -- OpenAI-compatible endpoint for review steps."""

    def __init__(self, api_key: str, model: str = "codex-5.4", base_url: str = "") -> None:
        resolved_url = base_url or os.environ.get(
            "CODEX_BASE_URL", "https://api.openai.com/v1"
        )
        super().__init__(api_key, model, base_url=resolved_url)


def create_client(provider: str, api_key: str, model: str = "", base_url: str = "") -> LLMClient:
    """Factory function to create the appropriate LLM client."""
    if provider == "anthropic":
        return AnthropicClient(api_key, model or "claude-sonnet-4-20250514")
    elif provider == "openai":
        return OpenAIClient(api_key, model or "gpt-4o", base_url=base_url)
    elif provider == "glm":
        return GLMClient(api_key, model or "glm-5.1", base_url=base_url)
    elif provider == "codex":
        return CodexClient(api_key, model or "codex-5.4", base_url=base_url)
    else:
        msg = f"Unsupported LLM provider: {provider}"
        raise ValueError(msg)
