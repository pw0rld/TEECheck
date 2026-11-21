package config

import (
	"flag"
	"os"
	"strings"
)

func recordLLMExplicitFlags(fs *flag.FlagSet, cfg Config) Config {
	if strings.TrimSpace(os.Getenv("TEECHECK_LLM_MAX_TOKENS")) != "" {
		cfg.LLMMaxTokensExplicit = true
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "llm-max-tokens" {
			cfg.LLMMaxTokensExplicit = true
		}
	})
	return cfg
}

// WithLLMSettingsFrom applies an already resolved role without losing whether
// its token budget was chosen explicitly or inferred for its model.
func (cfg Config) WithLLMSettingsFrom(role Config) Config {
	cfg.LLMProvider = role.LLMProvider
	cfg.LLMBaseURL = role.LLMBaseURL
	cfg.LLMAPIKey = role.LLMAPIKey
	cfg.LLMAPIKeyEnv = role.LLMAPIKeyEnv
	cfg.LLMModel = role.LLMModel
	cfg.LLMTransport = role.LLMTransport
	cfg.LLMReasoningEffort = role.LLMReasoningEffort
	cfg.LLMTimeoutSec = role.LLMTimeoutSec
	cfg.LLMTimeoutExplicit = role.LLMTimeoutExplicit
	cfg.LLMMaxTokens = role.LLMMaxTokens
	cfg.LLMMaxTokensExplicit = role.LLMMaxTokensExplicit
	cfg.llmMaxTokensDefaulted = role.llmMaxTokensDefaulted
	cfg.LLMTemp = role.LLMTemp
	return cfg
}
