package config

import "testing"

func TestWithLLMProviderDefaultsGLM(t *testing.T) {
	cfg := Config{
		LLMProvider: "z.ai",
		LLMAPIKey:   "test-key",
	}

	cfg = cfg.WithLLMProviderDefaults()

	if cfg.LLMProvider != LLMProviderGLM {
		t.Fatalf("expected normalized provider %q, got %q", LLMProviderGLM, cfg.LLMProvider)
	}
	if cfg.LLMBaseURL != defaultGLMBaseURL {
		t.Fatalf("expected GLM base URL %q, got %q", defaultGLMBaseURL, cfg.LLMBaseURL)
	}
	if cfg.LLMModel != defaultGLMModel {
		t.Fatalf("expected GLM default model %q, got %q", defaultGLMModel, cfg.LLMModel)
	}
}
