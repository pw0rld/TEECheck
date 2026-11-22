package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ContractPath string
	Command      string
	RunID        string
	RunDir       string
	Resume       bool
	RepoURL      string
	LocalPath    string
	Commit       string
	Focus        string
	// Hint is the caller's free-text concern, passed through to the
	// planner's system prompt. It biases what gets investigated; it never
	// narrows what gets modelled or scanned.
	Hint                  string
	OutputDir             string
	KnowledgeRoot         string
	GraphJSONPath         string
	MaxHotspots           int
	MaxCases              int
	MaxFindings           int
	AgentID               string
	LLMProvider           string
	LLMBaseURL            string
	LLMAPIKey             string
	LLMModel              string
	LLMTransport          string
	LLMReasoningEffort    string
	LLMTimeoutSec         int
	LLMTimeoutExplicit    bool
	LLMMaxTokens          int
	LLMMaxTokensExplicit  bool
	llmMaxTokensDefaulted bool
	LLMTemp               float64
	LLMStream             bool
	RoleConfigFile        string
	RoleOverrides         map[string]LLMRoleOverride
	LLMAPIKeyEnv          string
	StaticTools           string
	MaxDialogRounds       int
	Target                string
	Mode                  string
	// EnableLegacyPrior opts into the old architecture/invariant model stages.
	// The default pipeline grounds investigation in the project map and code.
	EnableLegacyPrior bool
	// Samples is the number of independent planner passes to run
	// per pipeline invocation. Default 1 = the legacy behavior.
	// With samples > 1, each pass after the first is told which
	// (file, symbol) pairs were already covered and asked to find
	// different ones; the union is deduped and fed to the 4-agent
	// downstream pipeline as a single case set.
	Samples int
	// Zero uses the Planner's default wall-clock allowance for each pass.
	PlannerWallClock time.Duration
	// Explicit zero disables only the corresponding token limit. An omitted
	// programmatic value retains the default so older Config literals work.
	PlannerMaxTokens                      int
	PlannerMaxTokensExplicit              bool
	PlannerMaxReconTokens                 int
	PlannerMaxReconTokensExplicit         bool
	PlannerMaxInvestigationTokens         int
	PlannerMaxInvestigationTokensExplicit bool
	// Programmatic zero leaves the default quota intact unless explicitly
	// requested. This distinguishes old Config literals from unlimited mode.
	MaxTaintQueries         int
	MaxTaintQueriesExplicit bool
	TaintQueryTimeout       time.Duration
	// Empty retains per-run source and database isolation.
	CodeQLCacheDir string
}

func Parse(args []string) (Config, error) {
	if len(args) == 0 {
		return Config{}, usageError("missing subcommand")
	}

	switch args[0] {
	case "knowledge-init":
		return parseKnowledgeInit(args[1:])
	case "init-run":
		return parseInitRun(args[1:])
	case "preprocess":
		return parsePreprocess(args[1:])
	case "mapper":
		return parseMapper(args[1:])
	case "map":
		return parseMap(args[1:])
	case "hotspots":
		return parseHotspots(args[1:])
	case "cases":
		return parseCases(args[1:])
	case "expert":
		return parseExpert(args[1:])
	case "challenge":
		return parseChallenge(args[1:])
	case "verifier":
		return parseVerifier(args[1:])
	case "arbiter":
		return parseArbiter(args[1:])
	case "report":
		return parseReport(args[1:])
	case "verify-contract":
		return parseVerifyContract(args[1:])
	case "validate-run":
		return parseValidateRun(args[1:])
	case "curator":
		return parseCurator(args[1:])
	case "run":
		return parseRun(args[1:])
	case "plan":
		return parsePlan(args[1:])
	case "review":
		return parseReview(args[1:])
	case "feedback":
		return parseFeedback(args[1:])
	default:
		return Config{}, usageError(fmt.Sprintf("unknown subcommand: %s", args[0]))
	}
}

func parseValidateRun(args []string) (Config, error) {
	fs := flag.NewFlagSet("validate-run", flag.ContinueOnError)
	cfg := Config{Command: "validate-run"}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory to validate")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("validate-run requires --run-dir")
	}
	return cfg, nil
}

func parseKnowledgeInit(args []string) (Config, error) {
	fs := flag.NewFlagSet("knowledge-init", flag.ContinueOnError)
	cfg := Config{
		Command:       "knowledge-init",
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory containing raw/wiki/learned")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseInitRun(args []string) (Config, error) {
	fs := flag.NewFlagSet("init-run", flag.ContinueOnError)
	cfg := Config{
		Command:       "init-run",
		Focus:         "tee",
		OutputDir:     filepath.Clean("runs"),
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.RunID, "run-id", "", "Stable run identifier; autogenerated when omitted")
	fs.StringVar(&cfg.RepoURL, "repo-url", "", "Repository URL associated with the run")
	fs.StringVar(&cfg.LocalPath, "local-path", "", "Local repository checkout path")
	fs.StringVar(&cfg.Commit, "commit", "", "Repository commit or revision under review")
	fs.StringVar(&cfg.Focus, "focus", cfg.Focus, "Audit focus area such as tee, runtime, attestation, or rofl")
	fs.StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Root directory where run folders are created")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory containing raw/wiki/learned")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RepoURL == "" {
		return Config{}, fmt.Errorf("init-run requires --repo-url")
	}
	if cfg.LocalPath == "" {
		return Config{}, fmt.Errorf("init-run requires --local-path")
	}
	if cfg.Commit == "" {
		return Config{}, fmt.Errorf("init-run requires --commit")
	}
	return cfg, nil
}

func parsePreprocess(args []string) (Config, error) {
	fs := flag.NewFlagSet("preprocess", flag.ContinueOnError)
	cfg := Config{Command: "preprocess"}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("preprocess requires --run-dir")
	}
	return cfg, nil
}

func parseMapper(args []string) (Config, error) {
	fs := flag.NewFlagSet("mapper", flag.ContinueOnError)
	cfg := Config{
		Command:     "mapper",
		MaxHotspots: 12,
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.GraphJSONPath, "graph-json", "", "Path to a GitNexus-style graph export JSON file")
	fs.IntVar(&cfg.MaxHotspots, "max-hotspots", cfg.MaxHotspots, "Maximum number of hotspots to emit")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("mapper requires --run-dir")
	}
	if cfg.GraphJSONPath == "" {
		return Config{}, fmt.Errorf("mapper requires --graph-json")
	}
	return cfg, nil
}

func parseMap(args []string) (Config, error) {
	fs := flag.NewFlagSet("map", flag.ContinueOnError)
	cfg := Config{Command: "map"}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.GraphJSONPath, "graph-json", "", "Path to a GitNexus-style graph export JSON file")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("map requires --run-dir")
	}
	if cfg.GraphJSONPath == "" {
		return Config{}, fmt.Errorf("map requires --graph-json")
	}
	return cfg, nil
}

func parseHotspots(args []string) (Config, error) {
	fs := flag.NewFlagSet("hotspots", flag.ContinueOnError)
	cfg := Config{
		Command:     "hotspots",
		MaxHotspots: 12,
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.IntVar(&cfg.MaxHotspots, "max-hotspots", cfg.MaxHotspots, "Maximum number of hotspots to emit")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("hotspots requires --run-dir")
	}
	return cfg, nil
}

func parseCases(args []string) (Config, error) {
	fs := flag.NewFlagSet("cases", flag.ContinueOnError)
	cfg := Config{
		Command:       "cases",
		MaxCases:      12,
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory containing raw/wiki/learned")
	fs.IntVar(&cfg.MaxCases, "max-cases", cfg.MaxCases, "Maximum number of case packs to emit")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("cases requires --run-dir")
	}
	return cfg, nil
}

func parseExpert(args []string) (Config, error) {
	fs := flag.NewFlagSet("expert", flag.ContinueOnError)
	cfg := Config{
		Command:       "expert",
		AgentID:       "expert-001",
		LLMProvider:   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:    firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:      firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec: envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:  envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:       envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.AgentID, "agent-id", cfg.AgentID, "Stable expert agent identifier")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset, such as openai, glm, or deepseek")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "OpenAI-compatible base URL; glm/deepseek presets fill this automatically")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "OpenAI-compatible API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Model name for the expert agent")
	registerStreamFlag(fs, &cfg)
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "HTTP timeout in seconds for the expert agent")
	fs.IntVar(&cfg.LLMMaxTokens, "llm-max-tokens", cfg.LLMMaxTokens, "Completion token budget per LLM call")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Sampling temperature for the expert agent")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("expert requires --run-dir")
	}
	if err := validateStreamConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseChallenge(args []string) (Config, error) {
	fs := flag.NewFlagSet("challenge", flag.ContinueOnError)
	cfg := Config{
		Command:       "challenge",
		AgentID:       "challenger-001",
		LLMProvider:   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:    firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:      firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec: envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:  envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:       envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.AgentID, "agent-id", cfg.AgentID, "Stable challenger agent identifier")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset, such as openai, glm, or deepseek")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "OpenAI-compatible base URL; glm/deepseek presets fill this automatically")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "OpenAI-compatible API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Model name for the challenger agent")
	registerStreamFlag(fs, &cfg)
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "HTTP timeout in seconds for the challenger agent")
	fs.IntVar(&cfg.LLMMaxTokens, "llm-max-tokens", cfg.LLMMaxTokens, "Completion token budget per LLM call")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Sampling temperature for the challenger agent")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("challenge requires --run-dir")
	}
	if err := validateStreamConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseVerifier(args []string) (Config, error) {
	fs := flag.NewFlagSet("verifier", flag.ContinueOnError)
	cfg := Config{
		Command:       "verifier",
		AgentID:       "verifier-001",
		LLMProvider:   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:    firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:      firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec: envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:  envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:       envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
		StaticTools:   "auto",
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.AgentID, "agent-id", cfg.AgentID, "Stable verifier agent identifier")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset, such as openai, glm, or deepseek")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "OpenAI-compatible base URL; glm/deepseek presets fill this automatically")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "OpenAI-compatible API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Model name for the verifier agent")
	registerStreamFlag(fs, &cfg)
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "HTTP timeout in seconds for the verifier agent")
	fs.IntVar(&cfg.LLMMaxTokens, "llm-max-tokens", cfg.LLMMaxTokens, "Completion token budget per LLM call")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Sampling temperature for the verifier agent")
	fs.StringVar(&cfg.StaticTools, "static-tools", cfg.StaticTools, "Static tools to enable: auto, none, or comma-separated names")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("verifier requires --run-dir")
	}
	if err := validateStreamConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseArbiter(args []string) (Config, error) {
	fs := flag.NewFlagSet("arbiter", flag.ContinueOnError)
	cfg := Config{
		Command:       "arbiter",
		AgentID:       "arbiter-001",
		MaxFindings:   0,
		LLMProvider:   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:    firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:      firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec: envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:  envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:       envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory created by init-run")
	fs.StringVar(&cfg.AgentID, "agent-id", cfg.AgentID, "Stable arbiter agent identifier")
	fs.IntVar(&cfg.MaxFindings, "max-findings", cfg.MaxFindings, "Maximum number of findings to emit; 0 means all")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset, such as openai, glm, or deepseek")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "OpenAI-compatible base URL; glm/deepseek presets fill this automatically")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "OpenAI-compatible API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Model name for the arbiter agent")
	registerStreamFlag(fs, &cfg)
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "HTTP timeout in seconds for the arbiter agent")
	fs.IntVar(&cfg.LLMMaxTokens, "llm-max-tokens", cfg.LLMMaxTokens, "Completion token budget per LLM call")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Sampling temperature for the arbiter agent")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("arbiter requires --run-dir")
	}
	if err := validateStreamConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseCurator(args []string) (Config, error) {
	fs := flag.NewFlagSet("curator", flag.ContinueOnError)
	cfg := Config{
		Command:            "curator",
		AgentID:            "curator-001",
		KnowledgeRoot:      filepath.Clean("knowledge"),
		MaxDialogRounds:    DefaultMaxDialogRounds,
		LLMProvider:        firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:         firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:          firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:           firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTransport:       firstNonEmptyEnv("TEECHECK_LLM_TRANSPORT"),
		LLMReasoningEffort: firstNonEmptyEnv("TEECHECK_LLM_REASONING_EFFORT"),
		LLMTimeoutSec:      envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:       envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:            envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing review outputs")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory")
	fs.StringVar(&cfg.AgentID, "agent-id", cfg.AgentID, "Stable curator agent identifier")
	fs.IntVar(&cfg.MaxDialogRounds, "max-dialog-rounds", cfg.MaxDialogRounds, "Maximum inter-agent dialog rounds per case, per asking agent")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset, such as openai, glm, or deepseek")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "OpenAI-compatible base URL; glm/deepseek presets fill this automatically")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "OpenAI-compatible API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Model name")
	registerStreamFlag(fs, &cfg)
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "HTTP timeout in seconds")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Sampling temperature")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("curator requires --run-dir")
	}
	if err := validateStreamConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseReport(args []string) (Config, error) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	cfg := Config{
		Command:       "report",
		Mode:          "llm",
		LLMProvider:   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:    firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:      firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec: envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:  envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:       envFloat(0.1, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing arbiter outputs")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "LLM base URL")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "LLM API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "LLM model name")
	registerStreamFlag(fs, &cfg)
	fs.StringVar(&cfg.LLMTransport, "llm-transport", cfg.LLMTransport, "OpenAI transport: chat_completions or responses")
	fs.StringVar(&cfg.LLMReasoningEffort, "llm-reasoning-effort", cfg.LLMReasoningEffort, "Reasoning effort for Responses models")
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "LLM timeout")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("report requires --run-dir")
	}
	if err := validateStreamConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseReview(args []string) (Config, error) {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	cfg := Config{
		Command:       "review",
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing arbiter outputs")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("review requires --run-dir")
	}
	return cfg, nil
}

func parseFeedback(args []string) (Config, error) {
	fs := flag.NewFlagSet("feedback", flag.ContinueOnError)
	cfg := Config{
		Command:       "feedback",
		KnowledgeRoot: filepath.Clean("knowledge"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing review outputs")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("feedback requires --run-dir")
	}
	return cfg, nil
}

func parseRun(args []string) (Config, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfg := Config{
		Command:                       "run",
		RepoURL:                       firstNonEmptyEnv("TEECHECK_REPO_URL"),
		Commit:                        firstNonEmptyEnv("TEECHECK_COMMIT"),
		Focus:                         "tee",
		OutputDir:                     filepath.Clean("runs"),
		KnowledgeRoot:                 filepath.Clean("knowledge"),
		MaxHotspots:                   12,
		MaxCases:                      12,
		MaxDialogRounds:               DefaultMaxDialogRounds,
		Mode:                          "llm",
		StaticTools:                   "auto",
		LLMProvider:                   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:                    firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:                     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:                      firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTransport:                  firstNonEmptyEnv("TEECHECK_LLM_TRANSPORT"),
		LLMReasoningEffort:            firstNonEmptyEnv("TEECHECK_LLM_REASONING_EFFORT"),
		LLMTimeoutSec:                 envInt(300, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMMaxTokens:                  envInt(0, "TEECHECK_LLM_MAX_TOKENS"),
		LLMTemp:                       envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
		Samples:                       1,
		PlannerMaxTokens:              240000,
		PlannerMaxReconTokens:         100000,
		PlannerMaxInvestigationTokens: 140000,
		MaxTaintQueries:               8,
		TaintQueryTimeout:             5 * time.Minute,
		CodeQLCacheDir:                firstNonEmptyEnv("TEECHECK_CODEQL_CACHE_DIR"),
	}
	fs.IntVar(&cfg.Samples, "samples", cfg.Samples, "Number of independent planner passes (LLM mode only); each pass avoids files+symbols from previous passes; downstream 4-agent pipeline runs once on the union")
	fs.DurationVar(&cfg.PlannerWallClock, "planner-wall-clock", 0, "Planner time allowance per pass, e.g. 10m or 30m (default 10m)")
	fs.IntVar(&cfg.PlannerMaxTokens, "planner-max-tokens", cfg.PlannerMaxTokens, "Maximum input plus output tokens per planner pass; 0 disables the aggregate token cap")
	fs.IntVar(&cfg.PlannerMaxReconTokens, "planner-max-recon-tokens", cfg.PlannerMaxReconTokens, "Maximum reconnaissance input plus output tokens per planner pass; 0 disables this phase token cap")
	fs.IntVar(&cfg.PlannerMaxInvestigationTokens, "planner-max-investigation-tokens", cfg.PlannerMaxInvestigationTokens, "Maximum investigation input plus output tokens per planner pass; 0 disables this phase token cap")
	fs.IntVar(&cfg.MaxTaintQueries, "max-taint-queries", cfg.MaxTaintQueries, "Maximum uncached taint queries per planner pass; 0 disables the separate query cap")
	fs.DurationVar(&cfg.TaintQueryTimeout, "taint-query-timeout", cfg.TaintQueryTimeout, "Timeout for each uncached taint query")
	fs.StringVar(&cfg.CodeQLCacheDir, "codeql-cache-dir", cfg.CodeQLCacheDir, "Optional shared immutable source/CodeQL database cache; queries use private run-local database copies")
	fs.StringVar(&cfg.RoleConfigFile, "role-config", os.Getenv("TEECHECK_ROLE_CONFIG"), "JSON file with startup-only per-role LLM overrides; credentials use api_key_env references")
	fs.StringVar(&cfg.Focus, "focus", cfg.Focus, "Audit focus area")
	fs.StringVar(&cfg.Hint, "hint", "", "Free-text concern to prioritise during planning, e.g. \"I suspect the TA loading path\"; does not narrow the scan")
	fs.BoolVar(&cfg.EnableLegacyPrior, "enable-legacy-prior", false, "Run legacy pre-investigation architecture and invariant model stages")
	fs.StringVar(&cfg.RunID, "run-id", "", "Stable run identifier")
	fs.BoolVar(&cfg.Resume, "resume", false, "Resume a checkpoint in --run-dir; repeat the original scan/model settings")
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Existing run directory for --resume")
	// Upstream identity overrides. Needed when the scanned directory is not
	// the project it represents — a benchmark fixture is a subtree of the
	// TEECheck repository, so git would label it with TEECheck's own origin
	// and HEAD instead of the CVE's upstream repository and revision.
	fs.StringVar(&cfg.RepoURL, "repo-url", cfg.RepoURL, "Upstream repository URL this source represents (overrides TEECHECK_REPO_URL and git detection)")
	fs.StringVar(&cfg.Commit, "commit", cfg.Commit, "Upstream revision this source represents (overrides TEECHECK_COMMIT and git detection)")
	fs.StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Output directory")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root")
	fs.IntVar(&cfg.MaxCases, "max-cases", cfg.MaxCases, "Maximum case packs")
	fs.IntVar(&cfg.MaxHotspots, "max-hotspots", cfg.MaxHotspots, "Maximum hotspots")
	fs.IntVar(&cfg.MaxDialogRounds, "max-dialog-rounds", cfg.MaxDialogRounds, "Maximum dialog rounds")
	fs.StringVar(&cfg.StaticTools, "static-tools", cfg.StaticTools, "Static tools")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider preset, such as openai, glm, or deepseek")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "LLM base URL")
	fs.Var(redactedKey{&cfg.LLMAPIKey}, "llm-api-key", "LLM API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "LLM model name")
	registerStreamFlag(fs, &cfg)
	fs.StringVar(&cfg.LLMTransport, "llm-transport", cfg.LLMTransport, "OpenAI transport: chat_completions or responses")
	fs.StringVar(&cfg.LLMReasoningEffort, "llm-reasoning-effort", cfg.LLMReasoningEffort, "Reasoning effort for Responses models")
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "LLM timeout")
	fs.IntVar(&cfg.LLMMaxTokens, "llm-max-tokens", cfg.LLMMaxTokens, "Completion token budget per LLM call")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "LLM temperature")
	// Extract target (non-flag arg) before parsing so it can appear anywhere
	var flagArgs []string
	var target string
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") && target == "" {
			// Check it's not a value for the previous flag
			previousTakesValue := false
			if i > 0 && strings.HasPrefix(args[i-1], "-") && !strings.Contains(args[i-1], "=") {
				previousTakesValue = true
				if f := fs.Lookup(strings.TrimLeft(args[i-1], "-")); f != nil {
					if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
						previousTakesValue = false
					}
				}
			}
			if previousTakesValue {
				flagArgs = append(flagArgs, args[i])
			} else {
				target = args[i]
			}
		} else {
			flagArgs = append(flagArgs, args[i])
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return Config{}, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "llm-timeout-seconds" {
			cfg.LLMTimeoutExplicit = true
		}
		if f.Name == "max-taint-queries" {
			cfg.MaxTaintQueriesExplicit = true
		}
		switch f.Name {
		case "planner-max-tokens":
			cfg.PlannerMaxTokensExplicit = true
		case "planner-max-recon-tokens":
			cfg.PlannerMaxReconTokensExplicit = true
		case "planner-max-investigation-tokens":
			cfg.PlannerMaxInvestigationTokensExplicit = true
		}
	})
	for _, limit := range []struct {
		name  string
		value int
	}{
		{"planner-max-tokens", cfg.PlannerMaxTokens},
		{"planner-max-recon-tokens", cfg.PlannerMaxReconTokens},
		{"planner-max-investigation-tokens", cfg.PlannerMaxInvestigationTokens},
	} {
		if limit.value < 0 {
			return Config{}, fmt.Errorf("--%s must be zero or positive", limit.name)
		}
	}
	if cfg.MaxTaintQueries < 0 {
		return Config{}, fmt.Errorf("--max-taint-queries must be zero or positive")
	}
	if cfg.TaintQueryTimeout <= 0 {
		return Config{}, fmt.Errorf("--taint-query-timeout must be positive")
	}
	if cfg.PlannerWallClock < 0 {
		return Config{}, fmt.Errorf("--planner-wall-clock must be positive")
	}
	var plannerWallClockSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "planner-wall-clock" {
			plannerWallClockSet = true
		}
	})
	if plannerWallClockSet && cfg.PlannerWallClock == 0 {
		return Config{}, fmt.Errorf("--planner-wall-clock must be positive")
	}
	if os.Getenv("TEECHECK_LLM_TIMEOUT_SECONDS") != "" {
		cfg.LLMTimeoutExplicit = true
	}
	cfg = recordLLMExplicitFlags(fs, cfg).WithLLMProviderDefaults()
	// Also check remaining args after flag parse
	if cfg.Resume && cfg.RunDir == "" {
		cfg.RunDir = target
	}
	if cfg.Resume && target == "" {
		target = cfg.RunDir
	}
	if cfg.RunDir != "" && !cfg.Resume {
		return Config{}, fmt.Errorf("--run-dir requires --resume")
	}
	if target == "" {
		remaining := fs.Args()
		if len(remaining) > 0 {
			target = remaining[0]
		}
	}
	if target == "" {
		return Config{}, fmt.Errorf("run requires a target (URL or local path)")
	}
	cfg.Target = target
	// When multi-sample is requested, auto-scale max-cases so the
	// downstream pipeline actually audits all discovered candidates
	// instead of silently truncating to a single-pass cap. The user
	// can still override with an explicit --max-cases value larger
	// than the auto-scaled one.
	if cfg.Samples > 1 && cfg.MaxCases <= 12 {
		cfg.MaxCases = cfg.Samples * cfg.MaxCases
	}
	if err := ValidatePipelineRoles(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parsePlan is a compatibility alias for the same LLM-backed run pipeline.
// Mode is fixed by parseRun; injecting a retired --mode flag breaks parsing.
func parsePlan(args []string) (Config, error) {
	cfg, err := parseRun(args)
	if err != nil {
		return Config{}, err
	}
	cfg.Command = "plan"
	return cfg, nil
}

func usageError(msg string) error {
	return fmt.Errorf("%s\n\nusage:\n  teecheck run <url-or-path> [--focus NAME] [--max-cases N] [--llm-provider openai|glm|deepseek] [--llm-base-url URL] [--llm-model NAME]\n  teecheck knowledge-init [--knowledge-root DIR]\n  teecheck init-run --repo-url URL --local-path PATH --commit SHA [--focus NAME] [--run-id ID] [--output-dir DIR] [--knowledge-root DIR]\n  teecheck preprocess --run-dir DIR\n  teecheck mapper --run-dir DIR --graph-json FILE [--max-hotspots N]\n  teecheck map --run-dir DIR --graph-json FILE\n  teecheck hotspots --run-dir DIR [--max-hotspots N]\n  teecheck cases --run-dir DIR [--knowledge-root DIR] [--max-cases N]\n  teecheck expert --run-dir DIR [--agent-id ID] [--llm-provider openai|glm|deepseek] [--llm-base-url URL] [--llm-model NAME]\n  teecheck challenge --run-dir DIR [--agent-id ID] [--llm-provider openai|glm|deepseek] [--llm-base-url URL] [--llm-model NAME]\n  teecheck verifier --run-dir DIR [--agent-id ID] [--llm-provider openai|glm|deepseek] [--llm-base-url URL] [--llm-model NAME]\n  teecheck arbiter --run-dir DIR [--agent-id ID] [--max-findings N]\n  teecheck validate-run --run-dir DIR\n  teecheck curator --run-dir DIR [--knowledge-root DIR] [--max-dialog-rounds N]\n  teecheck review --run-dir DIR [--knowledge-root DIR]\n  teecheck feedback --run-dir DIR [--knowledge-root DIR]", msg)
}

func validateProviderConfig(cfg Config, context string) error {
	cfg = cfg.WithLLMProviderDefaults()
	if cfg.LLMTransport != LLMTransportChatCompletions && cfg.LLMTransport != LLMTransportResponses {
		return fmt.Errorf("%s has unsupported LLM transport %q; use chat_completions or responses", context, cfg.LLMTransport)
	}
	if cfg.LLMTransport == LLMTransportResponses && cfg.LLMProvider != LLMProviderOpenAI {
		return fmt.Errorf("%s transport responses requires provider openai", context)
	}
	if err := validateStreamConfig(cfg); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	if cfg.LLMReasoningEffort != "" {
		deepSeekChat := cfg.LLMProvider == LLMProviderDeepSeek && cfg.LLMTransport == LLMTransportChatCompletions && DeepSeekSupportsThinkingControl(cfg.LLMModel)
		if cfg.LLMTransport != LLMTransportResponses && !deepSeekChat {
			return fmt.Errorf("%s reasoning effort requires the responses transport", context)
		}
		supported := map[string]bool{
			"none": true, "minimal": true, "low": true,
			"medium": true, "high": true, "xhigh": true,
		}
		if deepSeekChat {
			supported["max"] = true
		}
		if !supported[cfg.LLMReasoningEffort] {
			return fmt.Errorf("%s has unsupported reasoning effort %q", context, cfg.LLMReasoningEffort)
		}
	}
	if cfg.LLMBaseURL == "" {
		return fmt.Errorf("%s requires --llm-base-url or TEECHECK_LLM_BASE_URL when using llm mode", context)
	}
	if cfg.LLMAPIKey == "" {
		return fmt.Errorf("%s requires --llm-api-key or TEECHECK_LLM_API_KEY when using llm mode", context)
	}
	if cfg.LLMModel == "" {
		return fmt.Errorf("%s requires --llm-model or TEECHECK_LLM_MODEL when using llm mode", context)
	}
	return nil
}

// defaultLLMMaxTokens is the per-call completion budget. On a reasoning
// model this budget covers the model's own thinking as well as the answer:
// glm-5.2 spends reasoning_content first, so a budget consumed entirely by
// reasoning returns finish_reason "length" with empty content and kills the
// stage. 16384 was demonstrably too small — the expert stage exhausted it on
// a single case pack on 2026-07-29. Raised, and made configurable, because
// no fixed number is right for every model and prompt size.
// DefaultMaxDialogRounds is the per-case, per-asking-agent inter-agent
// dialog budget. It was 3 and shared across every stage, which was survivable
// only while scanner-001 — the one tool-backed bus agent — failed every query
// with "a prebuilt database is required". Once it started answering, the
// verifier spent the shared budget and the arbiter reported hitting the limit
// before it could ask about the rollback path at all.
const DefaultMaxDialogRounds = 10

const DefaultLLMMaxTokens = 32768

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func envInt(defaultValue int, keys ...string) int {
	for _, key := range keys {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
	}
	return defaultValue
}

func envFloat(defaultValue float64, keys ...string) float64 {
	for _, key := range keys {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return parsed
		}
	}
	return defaultValue
}

// redactedKey binds --llm-api-key without ever revealing what it holds.
//
// The flag package captures Value.String() at registration time and echoes it
// back as "(default …)" in every usage dump. Binding the key with StringVar
// therefore printed it to the terminal on --help and on ANY flag error — which
// happened for real on 2026-07-28, putting a live API key into a terminal and a
// task log. Returning "" here means the flag package sees a zero default and
// prints none, while cfg.LLMAPIKey keeps whatever the environment supplied.
type redactedKey struct{ p *string }

func (r redactedKey) String() string { return "" }

func (r redactedKey) Set(v string) error {
	if r.p != nil {
		*r.p = v
	}
	return nil
}

// registerStreamFlag opts in without changing existing endpoint behavior.
func registerStreamFlag(fs *flag.FlagSet, cfg *Config) {
	cfg.LLMStream = envBool(false, "TEECHECK_LLM_STREAM")
	fs.BoolVar(&cfg.LLMStream, "llm-stream", cfg.LLMStream, "Use SSE for OpenAI-compatible chat_completions; request final token usage")
}

func envBool(defaultValue bool, keys ...string) bool {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			if parsed, err := strconv.ParseBool(value); err == nil {
				return parsed
			}
		}
	}
	return defaultValue
}

func validateStreamConfig(cfg Config) error {
	if cfg.LLMStream && (cfg.LLMTransport != LLMTransportChatCompletions ||
		(cfg.LLMProvider != LLMProviderOpenAI && cfg.LLMProvider != LLMProviderDeepSeek)) {
		return fmt.Errorf("llm streaming requires an openai/deepseek provider with chat_completions transport")
	}
	return nil
}
