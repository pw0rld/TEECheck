package config

import "strings"

const (
	LLMProviderOpenAI           = "openai"
	LLMProviderGLM              = "glm"
	LLMTransportChatCompletions = "chat_completions"
	LLMTransportResponses       = "responses"

	defaultGLMBaseURL    = "https://api.z.ai/api/anthropic"
	defaultGLMModel      = "glm-4.7"
	defaultGLMTimeoutSec = 180
)

func NormalizeLLMProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", LLMProviderOpenAI:
		return LLMProviderOpenAI
	case LLMProviderGLM, "zai", "z.ai":
		return LLMProviderGLM
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func (cfg Config) WithLLMProviderDefaults() Config {
	cfg.LLMProvider = NormalizeLLMProvider(cfg.LLMProvider)
	cfg.LLMTransport = strings.ToLower(strings.TrimSpace(cfg.LLMTransport))
	cfg.LLMReasoningEffort = strings.ToLower(strings.TrimSpace(cfg.LLMReasoningEffort))
	if cfg.LLMTransport == "" {
		cfg.LLMTransport = LLMTransportChatCompletions
	}
	switch cfg.LLMProvider {
	case LLMProviderGLM:
		if strings.TrimSpace(cfg.LLMBaseURL) == "" {
			cfg.LLMBaseURL = defaultGLMBaseURL
		}
		if strings.TrimSpace(cfg.LLMModel) == "" {
			cfg.LLMModel = defaultGLMModel
		}
		// GLM-4.7 via the Z.AI Anthropic-compatible endpoint routinely
		// exceeds the project-wide 60s default on large prompts (verified
		// against mobilecoin: scanner stage OK, challenger first case
		// timed out). Bump the timeout to a GLM-friendly value when the
		// caller has not explicitly raised it above the global default.
		if cfg.LLMTimeoutSec <= 60 && !cfg.LLMTimeoutExplicit {
			cfg.LLMTimeoutSec = defaultGLMTimeoutSec
		}
	}
	return cfg
}
