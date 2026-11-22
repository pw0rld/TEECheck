package llm

import (
	"fmt"
	"os"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

// NewClient returns the configured provider client wrapped in a
// retry layer. The retry layer transparently handles transient
// server errors (5xx), connection resets, and timeouts with
// exponential backoff, so upstream agents don't have to implement
// their own retry logic.
func NewClient(cfg config.Config) Client {
	cfg = cfg.WithLLMProviderDefaults()
	var inner Client
	switch config.NormalizeLLMProvider(cfg.LLMProvider) {
	case config.LLMProviderGLM:
		inner = NewAnthropicClient(cfg)
	default:
		inner = NewOpenAIClient(cfg)
	}
	return NewRetryingClient(inner, RetryConfig{
		MaxAttempts: defaultRetryAttempts,
		BaseDelay:   5 * time.Second,
		MaxDelay:    90 * time.Second,
		Logger: func(attempt int, err error, wait time.Duration) {
			fmt.Fprintf(os.Stderr, "[llm] attempt %d failed (transient): %v — retrying in %s\n", attempt, err, wait)
		},
	})
}

// maxTokensOrDefault keeps a zero-valued config working. Callers that build
// a Config by hand — every test in this repo, and the standalone
// subcommands — leave LLMMaxTokens unset, and a max_tokens of 0 would be
// sent verbatim and rejected by the provider.
func maxTokensOrDefault(v int) int {
	if v > 0 {
		return v
	}
	return config.DefaultLLMMaxTokens
}
