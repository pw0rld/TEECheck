"""Configuration management for tee-audit."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel


class AuditConfig(BaseModel):
    """Runtime configuration for the audit pipeline."""

    llm_provider: Literal["anthropic", "openai"] = "anthropic"
    llm_api_key: str = ""
    llm_model: str = ""
    codeql_path: str = ""
    artifact_root: str = "/tmp/tee-audit"
    verbose: bool = False
    no_color: bool = False
    max_concurrent_llm_calls: int = 3

    @classmethod
    def load(cls, **overrides: object) -> AuditConfig:
        """Load config with priority: CLI args > env vars > config file > defaults."""
        data: dict = {}

        # Load from config file
        config_path = Path.home() / ".tee-audit" / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                file_data = yaml.safe_load(f) or {}
            data.update(file_data)

        # Override with env vars
        env_map = {
            "ANTHROPIC_API_KEY": "llm_api_key",
            "OPENAI_API_KEY": "llm_api_key",
            "TEE_AUDIT_CODEQL_PATH": "codeql_path",
            "TEE_AUDIT_ARTIFACT_ROOT": "artifact_root",
        }
        for env_var, config_key in env_map.items():
            value = os.environ.get(env_var)
            if value:
                data[config_key] = value

        # Auto-detect provider from which key is set
        if os.environ.get("OPENAI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
            data.setdefault("llm_provider", "openai")

        # Override with explicit args
        data.update({k: v for k, v in overrides.items() if v is not None})

        return cls(**data)
