package runinit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

// RoleLLMSnapshot intentionally has no credential-value field.
type RoleLLMSnapshot struct {
	Provider        string  `json:"provider"`
	BaseURL         string  `json:"base_url,omitempty"`
	Model           string  `json:"model,omitempty"`
	Transport       string  `json:"transport"`
	ReasoningEffort string  `json:"reasoning_effort,omitempty"`
	TimeoutSeconds  int     `json:"timeout_seconds"`
	MaxOutputTokens int     `json:"max_output_tokens"`
	Temperature     float64 `json:"temperature"`
	Stream          bool    `json:"stream,omitempty"`
	APIKeyPresent   bool    `json:"api_key_present"`
	APIKeyEnv       string  `json:"api_key_env,omitempty"`
}

// RecordRoleConfigurations preserves unrelated manifest fields, including
// independently-versioned stage and scope metadata.
func RecordRoleConfigurations(runDir string, settings map[string]config.Config) error {
	path := filepath.Join(runDir, "00_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	var metadata map[string]any
	if raw := manifest["metadata"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return err
		}
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	snapshots := map[string]RoleLLMSnapshot{}
	for _, role := range config.LLMRoles {
		cfg := settings[role]
		snapshots[role] = RoleLLMSnapshot{Provider: cfg.LLMProvider, BaseURL: config.RedactedEndpoint(cfg.LLMBaseURL), Model: cfg.LLMModel, Transport: cfg.LLMTransport, ReasoningEffort: cfg.LLMReasoningEffort, TimeoutSeconds: cfg.LLMTimeoutSec, MaxOutputTokens: cfg.LLMMaxTokens, Temperature: cfg.LLMTemp, Stream: cfg.LLMStream, APIKeyPresent: cfg.LLMAPIKey != "", APIKeyEnv: cfg.LLMAPIKeyEnv}
	}
	metadata["role_llm"] = snapshots
	manifest["metadata"], err = json.Marshal(metadata)
	if err != nil {
		return err
	}
	return writeJSON(path, manifest)
}
