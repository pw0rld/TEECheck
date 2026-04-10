package config

import "strings"

const (
	LLMProviderOpenAI = "openai"
	LLMProviderGLM    = "glm"

	defaultGLMBaseURL = "https://api.z.ai/api/anthropic"
	defaultGLMModel   = "glm-4.7"
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
	switch cfg.LLMProvider {
	case LLMProviderGLM:
		if strings.TrimSpace(cfg.LLMBaseURL) == "" {
			cfg.LLMBaseURL = defaultGLMBaseURL
		}
		if strings.TrimSpace(cfg.LLMModel) == "" {
			cfg.LLMModel = defaultGLMModel
		}
	}
	return cfg
}
