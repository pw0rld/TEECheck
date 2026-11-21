package config

import "strings"

const (
	LLMProviderOpenAI           = "openai"
	LLMProviderGLM              = "glm"
	LLMProviderDeepSeek         = "deepseek"
	LLMTransportChatCompletions = "chat_completions"
	LLMTransportResponses       = "responses"

	defaultGLMBaseURL               = "https://api.z.ai/api/anthropic"
	defaultGLMModel                 = "glm-4.7"
	defaultGLMTimeoutSec            = 180
	defaultDeepSeekBaseURL          = "https://api.deepseek.com/v1"
	defaultDeepSeekModel            = "deepseek-flash"
	legacyDeepSeekChatDefaultTokens = 8192
)

func NormalizeLLMProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", LLMProviderOpenAI:
		return LLMProviderOpenAI
	case LLMProviderGLM, "zai", "z.ai":
		return LLMProviderGLM
	case LLMProviderDeepSeek:
		return LLMProviderDeepSeek
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
	case LLMProviderDeepSeek:
		if strings.TrimSpace(cfg.LLMBaseURL) == "" {
			cfg.LLMBaseURL = defaultDeepSeekBaseURL
		}
		if strings.TrimSpace(cfg.LLMModel) == "" {
			cfg.LLMModel = defaultDeepSeekModel
		}
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
	// Preserve explicit CLI/environment/role budgets and non-default positive
	// programmatic budgets. A programmatic budget equal to the global default
	// needs LLMMaxTokensExplicit to distinguish it from an inherited default.
	// Recompute inferred defaults when a role switches models so one role's
	// legacy cap cannot leak to another.
	if cfg.LLMMaxTokens <= 0 || (!cfg.LLMMaxTokensExplicit && (cfg.llmMaxTokensDefaulted || cfg.LLMMaxTokens == DefaultLLMMaxTokens)) {
		cfg.LLMMaxTokens = DefaultLLMMaxTokens
		if strings.EqualFold(strings.TrimSpace(cfg.LLMModel), "deepseek-chat") {
			cfg.LLMMaxTokens = legacyDeepSeekChatDefaultTokens
		}
		cfg.llmMaxTokensDefaulted = true
	}
	return cfg
}

// DeepSeekThinkingModel identifies documented thinking-by-default aliases.
// Do not infer capabilities from an arbitrary model name containing "reason".
func DeepSeekThinkingModel(model string) bool {
	switch strings.ToLower(strings.TrimSpace(model)) {
	case "deepseek-reasoner", "deepseek-flash", "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v4-flash-vision-exp":
		return true
	default:
		return false
	}
}

func DeepSeekSupportsThinkingControl(model string) bool {
	return DeepSeekThinkingModel(model) && !strings.EqualFold(strings.TrimSpace(model), "deepseek-reasoner")
}
