"""Tests for configuration loading."""

from __future__ import annotations

import os
from pathlib import Path

from tee_audit.config import AuditConfig


class TestAuditConfig:
    def test_defaults(self):
        config = AuditConfig.load()
        assert config.llm_provider == "anthropic"
        assert config.max_concurrent_llm_calls == 3
        assert config.verbose is False

    def test_overrides(self):
        config = AuditConfig.load(verbose=True, llm_provider="openai")
        assert config.verbose is True
        assert config.llm_provider == "openai"

    def test_env_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        config = AuditConfig.load()
        assert config.llm_api_key == "test-key-123"

    def test_env_codeql_path(self, monkeypatch):
        monkeypatch.setenv("TEE_AUDIT_CODEQL_PATH", "/usr/local/bin/codeql")
        config = AuditConfig.load()
        assert config.codeql_path == "/usr/local/bin/codeql"

    def test_openai_auto_detect(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
        config = AuditConfig.load()
        assert config.llm_provider == "openai"
        assert config.llm_api_key == "openai-key"

    def test_none_overrides_ignored(self):
        config = AuditConfig.load(verbose=None, llm_api_key=None)
        # Should not crash, defaults preserved
        assert config.llm_provider == "anthropic"

    def test_config_file(self, tmp_path: Path, monkeypatch):
        config_dir = tmp_path / ".tee-audit"
        config_dir.mkdir()
        config_file = config_dir / "config.yaml"
        config_file.write_text("llm_provider: openai\nverbose: true\n")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        config = AuditConfig.load()
        assert config.llm_provider == "openai"
        assert config.verbose is True
