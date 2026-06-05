"""Tests for GLM and Codex LLM provider clients."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tee_audit.llm.client import GLMClient, CodexClient, OpenAIClient, create_client


class TestGLMClient:
    def test_default_base_url(self):
        client = GLMClient(api_key="test-key")
        assert client._base_url == "https://open.bigmodel.cn/api/paas/v4"

    def test_custom_base_url(self):
        client = GLMClient(api_key="test-key", base_url="https://custom.glm.api")
        assert client._base_url == "https://custom.glm.api"

    @patch.dict("os.environ", {"GLM_BASE_URL": "https://env.glm.api"})
    def test_env_base_url(self):
        client = GLMClient(api_key="test-key")
        assert client._base_url == "https://env.glm.api"

    def test_inherits_openai_client(self):
        assert issubclass(GLMClient, OpenAIClient)

    def test_create_client_dispatch(self):
        client = create_client("glm", "test-key")
        assert isinstance(client, GLMClient)


class TestCodexClient:
    def test_default_base_url(self):
        client = CodexClient(api_key="test-key")
        assert client._base_url == "https://api.openai.com/v1"

    def test_custom_base_url(self):
        client = CodexClient(api_key="test-key", base_url="https://custom.codex.api")
        assert client._base_url == "https://custom.codex.api"

    @patch.dict("os.environ", {"CODEX_BASE_URL": "https://env.codex.api"})
    def test_env_base_url(self):
        client = CodexClient(api_key="test-key")
        assert client._base_url == "https://env.codex.api"

    def test_inherits_openai_client(self):
        assert issubclass(CodexClient, OpenAIClient)

    def test_create_client_dispatch(self):
        client = create_client("codex", "test-key")
        assert isinstance(client, CodexClient)


class TestCreateClient:
    def test_anthropic_dispatch(self):
        client = create_client("anthropic", "test-key")
        from tee_audit.llm.client import AnthropicClient
        assert isinstance(client, AnthropicClient)

    def test_openai_dispatch(self):
        client = create_client("openai", "test-key")
        assert isinstance(client, OpenAIClient)

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unsupported LLM provider"):
            create_client("unknown", "test-key")

    def test_base_url_forwarded(self):
        client = create_client("openai", "test-key", base_url="https://custom.api")
        assert client._base_url == "https://custom.api"
