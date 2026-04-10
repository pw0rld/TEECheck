package llm

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"

func NewClient(cfg config.Config) Client {
	cfg = cfg.WithLLMProviderDefaults()
	switch config.NormalizeLLMProvider(cfg.LLMProvider) {
	case config.LLMProviderGLM:
		return NewAnthropicClient(cfg)
	default:
		return NewOpenAIClient(cfg)
	}
}
