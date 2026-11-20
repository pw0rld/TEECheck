package config

import (
	"flag"
	"fmt"
	"os"
)

func parseVerifyContract(args []string) (Config, error) {
	fs := flag.NewFlagSet("verify-contract", flag.ContinueOnError)
	cfg := Config{Command: "verify-contract", OutputDir: "contract-rechecks", Focus: "tee", Mode: "llm", LLMProvider: firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"), LLMBaseURL: firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"), LLMAPIKey: firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"), LLMModel: firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"), LLMTransport: os.Getenv("TEECHECK_LLM_TRANSPORT"), LLMTimeoutSec: 60, LLMMaxTokens: DefaultLLMMaxTokens, LLMTemp: 0.2}
	fs.StringVar(&cfg.ContractPath, "contract", "", "Standalone CaseInvariantV2 JSON file")
	fs.StringVar(&cfg.LocalPath, "repo-root", "", "Local fixed-revision source directory")
	fs.StringVar(&cfg.RepoURL, "repo-url", "", "Repository identity of the fixed source")
	fs.StringVar(&cfg.Commit, "commit", "", "Commit represented by the fixed source (defaults to local Git HEAD)")
	fs.StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Independent output root; never an existing scan run or knowledge directory")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "Optional Verifier provider")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "Optional Verifier API base URL")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "Optional Verifier API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Optional Verifier model")
	fs.StringVar(&cfg.LLMTransport, "llm-transport", cfg.LLMTransport, "OpenAI transport")
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "Verifier request timeout")
	fs.IntVar(&cfg.LLMMaxTokens, "llm-max-tokens", cfg.LLMMaxTokens, "Verifier completion budget")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Verifier temperature")
	fs.StringVar(&cfg.RoleConfigFile, "role-config", os.Getenv("TEECHECK_ROLE_CONFIG"), "Optional startup-only Verifier role override")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("verify-contract accepts flags only")
	}
	if cfg.ContractPath == "" || cfg.LocalPath == "" {
		return Config{}, fmt.Errorf("verify-contract requires --contract and --repo-root")
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "llm-timeout-seconds" {
			cfg.LLMTimeoutExplicit = true
		}
	})
	return cfg.WithLLMProviderDefaults(), nil
}
