"""Tests for configuration loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tee_audit.config import AuditConfig


class TestAuditConfig:
    def test_defaults(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("CODEX_API_KEY", raising=False)
        config = AuditConfig.load()
        assert config.llm_provider == "anthropic"
        assert config.max_concurrent_llm_calls == 3
        assert config.verbose is False
        assert config.artifact_root == "output"

    def test_overrides(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        config = AuditConfig.load(verbose=True, llm_provider="openai")
        assert config.verbose is True
        assert config.llm_provider == "openai"

    def test_env_api_key(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        config = AuditConfig.load()
        assert config.llm_api_key == "test-key-123"

    def test_env_codeql_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        monkeypatch.setenv("TEE_AUDIT_CODEQL_PATH", "/usr/local/bin/codeql")
        config = AuditConfig.load()
        assert config.codeql_path == "/usr/local/bin/codeql"

    def test_openai_auto_detect(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
        config = AuditConfig.load()
        assert config.llm_provider == "openai"
        assert config.llm_api_key == "openai-key"

    def test_none_overrides_ignored(self, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = AuditConfig.load(verbose=None, llm_api_key=None)
        assert config.llm_provider == "anthropic"

    def test_config_file(self, tmp_path: Path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("llm_provider: openai\nverbose: true\n")

        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        monkeypatch.delenv("GLM_API_KEY", raising=False)
        config = AuditConfig.load()
        assert config.llm_provider == "openai"
        assert config.verbose is True
