"""Configuration management for tee-audit."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel


class AuditConfig(BaseModel):
    """Runtime configuration for the audit pipeline."""

    llm_provider: Literal["anthropic", "openai", "glm", "codex"] = "anthropic"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""
    codeql_path: str = ""
    artifact_root: str = "output"
    verbose: bool = False
    no_color: bool = False
    max_concurrent_llm_calls: int = 3
    no_escalate: bool = False
    # Per-repo subsystem scoping: repo name -> list of repo-relative path prefixes
    # to enumerate (e.g. {"suave-geth": ["suave/"]}). Restricts a fork's analysis
    # to its own enclave/trust layer so inherited code is not mislabeled. A repo
    # not listed (or []) = whole repo (backward compatible).
    repo_scopes: dict[str, list[str]] = {}

    @classmethod
    def load(cls, **overrides: object) -> AuditConfig:
        """Load config with priority: CLI args > env vars > local config file > defaults."""
        data: dict = {}

        # Load from local config file (./config.yaml in CWD)
        config_path = Path.cwd() / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                data.update(yaml.safe_load(f) or {})

        # Override with env vars (non-conflicting mappings only)
        env_map = {
            "TEE_AUDIT_CODEQL_PATH": "codeql_path",
            "TEE_AUDIT_ARTIFACT_ROOT": "artifact_root",
        }
        for env_var, config_key in env_map.items():
            value = os.environ.get(env_var)
            if value:
                data[config_key] = value

        # Auto-detect provider from which key is set
        provider_key_env = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "glm": "GLM_API_KEY",
            "codex": "CODEX_API_KEY",
        }
        # Detect provider from first available key
        if os.environ.get("OPENAI_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
            data.setdefault("llm_provider", "openai")
        if os.environ.get("GLM_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
            data.setdefault("llm_provider", "glm")
        if os.environ.get("CODEX_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
            data.setdefault("llm_provider", "codex")

        # Select API key based on active provider
        provider = data.get("llm_provider", "anthropic")
        if provider in provider_key_env and not data.get("llm_api_key"):
            data["llm_api_key"] = os.environ.get(provider_key_env[provider], "")

        # Select base URL based on provider
        provider_base_url_env = {"glm": "GLM_BASE_URL", "codex": "CODEX_BASE_URL"}
        if provider in provider_base_url_env and not data.get("llm_base_url"):
            data["llm_base_url"] = os.environ.get(provider_base_url_env[provider], "")

        # Override with explicit args
        data.update({k: v for k, v in overrides.items() if v is not None})

        return cls(**data)
