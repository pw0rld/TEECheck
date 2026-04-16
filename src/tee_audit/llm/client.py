"""LLM client abstraction — Anthropic and OpenAI with structured output support."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMClient(ABC):
    """Abstract LLM client with basic and structured completion support."""

    def __init__(self, api_key: str, model: str = "") -> None:
        self.api_key = api_key
        self.model = model
        self.total_tokens_used = 0

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

    def complete(self, system: str, user: str, temperature: float = 0) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)
        response = client.messages.create(
            model=self.model,
            max_tokens=4096,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        self.total_tokens_used += getattr(response.usage, "input_tokens", 0) + getattr(response.usage, "output_tokens", 0)
        return response.content[0].text

    def complete_structured(
        self, system: str, user: str, schema: type[T], temperature: float = 0
    ) -> T:
        """Use Anthropic tool use to get structured JSON output."""
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)

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

        self.total_tokens_used += getattr(response.usage, "input_tokens", 0) + getattr(response.usage, "output_tokens", 0)

        # Extract tool use block
        for block in response.content:
            if block.type == "tool_use":
                return schema.model_validate(block.input)

        # Fallback: try to parse text as JSON
        text = "".join(b.text for b in response.content if hasattr(b, "text"))
        return schema.model_validate_json(text)

    def count_tokens(self, text: str) -> int:
        # Rough estimate: ~4 chars per token
        return len(text) // 4


class OpenAIClient(LLMClient):
    """OpenAI API client using function calling for structured output."""

    def __init__(self, api_key: str, model: str = "gpt-4o") -> None:
        super().__init__(api_key, model)

    def complete(self, system: str, user: str, temperature: float = 0) -> str:
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key)
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
            self.total_tokens_used += usage.total_tokens
        return response.choices[0].message.content or ""

    def complete_structured(
        self, system: str, user: str, schema: type[T], temperature: float = 0
    ) -> T:
        """Use OpenAI function calling to get structured JSON output."""
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key)
        json_schema = schema.model_json_schema()

        response = client.chat.completions.create(
            model=self.model,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            functions=[{
                "name": schema.__name__,
                "description": f"Respond with a structured {schema.__name__} object.",
                "parameters": json_schema,
            }],
            function_call={"name": schema.__name__},
        )

        usage = response.usage
        if usage:
            self.total_tokens_used += usage.total_tokens

        func_call = response.choices[0].message.function_call
        if func_call and func_call.arguments:
            return schema.model_validate_json(func_call.arguments)

        # Fallback
        text = response.choices[0].message.content or "{}"
        return schema.model_validate_json(text)

    def count_tokens(self, text: str) -> int:
        return len(text) // 4


def create_client(provider: str, api_key: str, model: str = "") -> LLMClient:
    """Factory function to create the appropriate LLM client."""
    if provider == "anthropic":
        return AnthropicClient(api_key, model or "claude-sonnet-4-20250514")
    elif provider == "openai":
        return OpenAIClient(api_key, model or "gpt-4o")
    else:
        msg = f"Unsupported LLM provider: {provider}"
        raise ValueError(msg)
