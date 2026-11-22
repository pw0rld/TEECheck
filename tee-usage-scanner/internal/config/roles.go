package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// LLMRoles are fixed at startup. Policy refusals never change their routing.
var LLMRoles = []string{"planner", "expert", "challenger", "verifier", "arbiter"}

// LLMRoleOverride has no credential value: api_key_env is an environment
// reference. Omitted fields inherit globals; pointers preserve explicit zero.
type LLMRoleOverride struct {
	Provider        string   `json:"provider,omitempty"`
	BaseURL         string   `json:"base_url,omitempty"`
	Model           string   `json:"model,omitempty"`
	Transport       string   `json:"transport,omitempty"`
	APIKeyEnv       string   `json:"api_key_env,omitempty"`
	TimeoutSeconds  *int     `json:"timeout_seconds,omitempty"`
	MaxOutputTokens *int     `json:"max_output_tokens,omitempty"`
	Temperature     *float64 `json:"temperature,omitempty"`
	ReasoningEffort *string  `json:"reasoning_effort,omitempty"`
	Stream          *bool    `json:"stream,omitempty"`
}

var credentialEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func knownRole(role string) bool {
	for _, candidate := range LLMRoles {
		if role == candidate {
			return true
		}
	}
	return false
}

func readRoleOverrides(path string) (map[string]LLMRoleOverride, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read role config: %w", err)
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var overrides map[string]LLMRoleOverride
	if err := decoder.Decode(&overrides); err != nil {
		return nil, fmt.Errorf("decode role config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("role config must contain one JSON object")
	}
	return overrides, nil
}

// ResolveRoleConfigs freezes inherited settings and credential references for
// one run. Required credentials are checked separately so fake clients remain
// usable for offline tests.
func (cfg Config) ResolveRoleConfigs() (map[string]Config, error) {
	file, err := readRoleOverrides(cfg.RoleConfigFile)
	if err != nil {
		return nil, err
	}
	for _, overrides := range []map[string]LLMRoleOverride{file, cfg.RoleOverrides} {
		for role := range overrides {
			if !knownRole(role) {
				return nil, fmt.Errorf("unknown LLM role %q", role)
			}
		}
	}
	base := cfg.WithLLMProviderDefaults()
	if base.LLMTimeoutSec <= 0 {
		base.LLMTimeoutSec = 60
	}
	if base.LLMMaxTokens <= 0 {
		base.LLMMaxTokens = DefaultLLMMaxTokens
	}
	resolved := make(map[string]Config, len(LLMRoles))
	for _, role := range LLMRoles {
		current := base
		for _, override := range []LLMRoleOverride{file[role], cfg.RoleOverrides[role]} {
			current, err = applyRoleOverride(current, override)
			if err != nil {
				return nil, fmt.Errorf("%s role: %w", role, err)
			}
		}
		current = current.WithLLMProviderDefaults()
		if current.LLMProvider != LLMProviderOpenAI && current.LLMProvider != LLMProviderGLM && current.LLMProvider != LLMProviderDeepSeek {
			return nil, fmt.Errorf("%s role has unsupported provider %q", role, current.LLMProvider)
		}
		if err := validateStreamConfig(current); err != nil {
			return nil, fmt.Errorf("%s role: %w", role, err)
		}
		resolved[role] = current
	}
	return resolved, nil
}

func applyRoleOverride(cfg Config, override LLMRoleOverride) (Config, error) {
	if override.Provider != "" {
		cfg.LLMProvider = override.Provider
	}
	if override.BaseURL != "" {
		cfg.LLMBaseURL = override.BaseURL
	}
	if override.Model != "" {
		cfg.LLMModel = override.Model
	}
	if override.Transport != "" {
		cfg.LLMTransport = override.Transport
	}
	if override.Stream != nil {
		cfg.LLMStream = *override.Stream
	}
	if override.ReasoningEffort != nil {
		cfg.LLMReasoningEffort = *override.ReasoningEffort
	}
	if override.TimeoutSeconds != nil {
		if *override.TimeoutSeconds <= 0 {
			return cfg, fmt.Errorf("timeout_seconds must be positive")
		}
		cfg.LLMTimeoutSec = *override.TimeoutSeconds
		cfg.LLMTimeoutExplicit = true
	}
	if override.MaxOutputTokens != nil {
		if *override.MaxOutputTokens <= 0 {
			return cfg, fmt.Errorf("max_output_tokens must be positive")
		}
		cfg.LLMMaxTokens = *override.MaxOutputTokens
		cfg.LLMMaxTokensExplicit = true
		cfg.llmMaxTokensDefaulted = false
	}
	if override.Temperature != nil {
		if *override.Temperature < 0 || *override.Temperature > 2 {
			return cfg, fmt.Errorf("temperature must be between 0 and 2")
		}
		cfg.LLMTemp = *override.Temperature
	}
	if override.APIKeyEnv != "" {
		if !credentialEnvironmentName.MatchString(override.APIKeyEnv) {
			return cfg, fmt.Errorf("api_key_env must name an environment variable")
		}
		value := os.Getenv(override.APIKeyEnv)
		if value == "" {
			return cfg, fmt.Errorf("credential environment variable %s is empty or unset", override.APIKeyEnv)
		}
		cfg.LLMAPIKey = value
		cfg.LLMAPIKeyEnv = override.APIKeyEnv
	}
	return cfg, nil
}

func ValidatePipelineRoles(cfg Config) error {
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		return err
	}
	return ValidateResolvedRoles(roles)
}

func ValidateResolvedRoles(roles map[string]Config) error {
	for _, role := range LLMRoles {
		if err := validateProviderConfig(roles[role], role+" role"); err != nil {
			return err
		}
	}
	return nil
}

// RedactedEndpoint drops URL credentials, query tokens and fragments before
// the endpoint is copied into a durable manifest.
func RedactedEndpoint(endpoint string) string {
	if strings.TrimSpace(endpoint) == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "(invalid endpoint)"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
