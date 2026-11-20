package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleConfigsInheritAndResolveCredentialReferences(t *testing.T) {
	t.Setenv("TEST_PLANNER_KEY", "role-secret")
	timeout, output, temperature := 25, 8192, 0.0
	cfg := Config{LLMProvider: "openai", LLMBaseURL: "https://global.invalid/v1", LLMAPIKey: "global-secret", LLMModel: "global-model", LLMTimeoutSec: 300, LLMMaxTokens: 32768, LLMTemp: 0.2,
		RoleOverrides: map[string]LLMRoleOverride{
			"planner": {Provider: "glm", BaseURL: "https://planner.invalid/api", Model: "planner-model", APIKeyEnv: "TEST_PLANNER_KEY", TimeoutSeconds: &timeout, MaxOutputTokens: &output, Temperature: &temperature},
			"expert":  {Model: "expert-model"},
		},
	}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	p := roles["planner"]
	if p.LLMProvider != "glm" || p.LLMModel != "planner-model" || p.LLMAPIKey != "role-secret" || p.LLMTimeoutSec != 25 || p.LLMMaxTokens != 8192 || p.LLMTemp != 0 {
		t.Fatalf("planner override lost: %+v", p)
	}
	if got := roles["expert"]; got.LLMModel != "expert-model" || got.LLMAPIKey != "global-secret" || got.LLMBaseURL != cfg.LLMBaseURL {
		t.Fatal("expert did not inherit global settings")
	}
	if roles["verifier"].LLMModel != "global-model" || cfg.LLMModel != "global-model" {
		t.Fatal("global config changed during role resolution")
	}
}

func TestParseRunAcceptsCompleteRoleFileWithoutGlobalCredentials(t *testing.T) {
	for _, key := range []string{"TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL", "TEECHECK_LLM_API_KEY", "OPENAI_API_KEY", "TEECHECK_LLM_MODEL", "OPENAI_MODEL", "TEECHECK_ROLE_CONFIG"} {
		t.Setenv(key, "")
	}
	t.Setenv("TEST_ROLE_KEY", "file-secret")
	path := filepath.Join(t.TempDir(), "roles.json")
	if err := os.WriteFile(path, []byte(`{"planner":{"base_url":"https://model.invalid/v1","model":"planner","api_key_env":"TEST_ROLE_KEY"},"expert":{"base_url":"https://model.invalid/v1","model":"expert","api_key_env":"TEST_ROLE_KEY"},"challenger":{"base_url":"https://model.invalid/v1","model":"challenger","api_key_env":"TEST_ROLE_KEY"},"verifier":{"base_url":"https://model.invalid/v1","model":"verifier","api_key_env":"TEST_ROLE_KEY"},"arbiter":{"base_url":"https://model.invalid/v1","model":"arbiter","api_key_env":"TEST_ROLE_KEY"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"run", ".", "--role-config", path})
	if err != nil {
		t.Fatal(err)
	}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if roles["arbiter"].LLMModel != "arbiter" {
		t.Fatal("role file was not applied")
	}
}

func TestRoleFileRejectsInlineSecretsUnknownRolesAndMissingReferences(t *testing.T) {
	for _, body := range []string{`{"planner":{"api_key":"do-not-leak-this"}}`, `{"unknown":{"model":"x"}}`, `{"planner":{"api_key_env":"UNDEFINED_TEST_ROLE_SECRET"}}`} {
		path := filepath.Join(t.TempDir(), "roles.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := (Config{RoleConfigFile: path}).ResolveRoleConfigs()
		if err == nil {
			t.Fatalf("invalid role settings accepted: %s", body)
		}
		if strings.Contains(err.Error(), "do-not-leak-this") {
			t.Fatal("inline secret leaked in error")
		}
	}
}

func TestRedactedEndpointDropsCredentialsAndQuery(t *testing.T) {
	got := RedactedEndpoint("https://user:secret@example.invalid/v1?api_key=secret#secret")
	if got != "https://example.invalid/v1" {
		t.Fatalf("not redacted: %q", got)
	}
}
