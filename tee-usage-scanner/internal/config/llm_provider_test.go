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

func TestWithLLMProviderDefaultsGLMTimeoutBumped(t *testing.T) {
	// When provider=glm and timeout is at or below the global default (60),
	// bump it to a GLM-friendly value because GLM-4.7 routinely takes longer
	// than 60s on large prompts (verified against mobilecoin via the Z.AI
	// Anthropic-compatible endpoint).
	cfg := Config{
		LLMProvider:   LLMProviderGLM,
		LLMTimeoutSec: 60,
	}

	cfg = cfg.WithLLMProviderDefaults()

	if cfg.LLMTimeoutSec != defaultGLMTimeoutSec {
		t.Fatalf("expected GLM default timeout %d, got %d", defaultGLMTimeoutSec, cfg.LLMTimeoutSec)
	}
}

func TestWithLLMProviderDefaultsGLMTimeoutRespectsExplicit(t *testing.T) {
	// If the user explicitly passes a longer timeout, do not shrink it.
	cfg := Config{
		LLMProvider:   LLMProviderGLM,
		LLMTimeoutSec: 600,
	}

	cfg = cfg.WithLLMProviderDefaults()

	if cfg.LLMTimeoutSec != 600 {
		t.Fatalf("expected explicit timeout 600 preserved, got %d", cfg.LLMTimeoutSec)
	}
}

func TestWithLLMProviderDefaultsOpenAITimeoutUnchanged(t *testing.T) {
	// Bump only applies to GLM, not OpenAI.
	cfg := Config{
		LLMProvider:   LLMProviderOpenAI,
		LLMTimeoutSec: 60,
	}

	cfg = cfg.WithLLMProviderDefaults()

	if cfg.LLMTimeoutSec != 60 {
		t.Fatalf("expected OpenAI timeout 60 unchanged, got %d", cfg.LLMTimeoutSec)
	}
}
