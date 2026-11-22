package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func streamTestEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER", "TEECHECK_LLM_TRANSPORT", "TEECHECK_LLM_REASONING_EFFORT", "TEECHECK_LLM_STREAM", "TEECHECK_ROLE_CONFIG"} {
		t.Setenv(key, "")
	}
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
}

func TestStreamFlagDefaultsEnvironmentAndOverrides(t *testing.T) {
	streamTestEnvironment(t)
	cfg, err := Parse([]string{"run", "."})
	if err != nil || cfg.LLMStream {
		t.Fatalf("default: stream=%v err=%v", cfg.LLMStream, err)
	}
	t.Setenv("TEECHECK_LLM_STREAM", "true")
	cfg, err = Parse([]string{"run", "."})
	if err != nil || !cfg.LLMStream {
		t.Fatalf("env: stream=%v err=%v", cfg.LLMStream, err)
	}
	cfg, err = Parse([]string{"run", "--llm-stream=false", "."})
	if err != nil || cfg.LLMStream {
		t.Fatalf("explicit false: stream=%v err=%v", cfg.LLMStream, err)
	}
	t.Setenv("TEECHECK_LLM_STREAM", "")
	cfg, err = Parse([]string{"run", "--llm-stream", "."})
	if err != nil || !cfg.LLMStream {
		t.Fatalf("boolean flag before target: stream=%v err=%v", cfg.LLMStream, err)
	}
}

func TestStreamFlagOnStandaloneLLMCommands(t *testing.T) {
	streamTestEnvironment(t)
	for _, command := range []string{"expert", "challenge", "verifier", "arbiter", "curator", "report", "verify-contract", "plan"} {
		t.Run(command, func(t *testing.T) {
			args := []string{command, "--llm-stream", "--run-dir", "run"}
			if command == "verify-contract" {
				args = []string{command, "--llm-stream", "--contract", "contract.json", "--repo-root", "repo"}
			}
			if command == "plan" {
				args = []string{command, ".", "--llm-stream"}
			}
			cfg, err := Parse(args)
			if err != nil || !cfg.LLMStream {
				t.Fatalf("stream=%v err=%v", cfg.LLMStream, err)
			}
		})
	}
}

func TestStreamRoleInheritanceAndExplicitFalse(t *testing.T) {
	streamTestEnvironment(t)
	path := filepath.Join(t.TempDir(), "roles.json")
	if err := os.WriteFile(path, []byte(`{"planner":{"stream":false},"expert":{"stream":true},"challenger":{"provider":"glm","stream":false}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"run", ".", "--llm-stream", "--role-config", path})
	if err != nil {
		t.Fatal(err)
	}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if roles["planner"].LLMStream || !roles["expert"].LLMStream || !roles["verifier"].LLMStream || roles["challenger"].LLMStream {
		t.Fatalf("lost explicit/inherited stream settings: %+v", roles)
	}
	copied := cfg.WithLLMSettingsFrom(roles["planner"])
	if copied.LLMStream {
		t.Fatal("role copy lost explicit false")
	}
}

func TestStreamRejectsUnsupportedProvidersAndTransports(t *testing.T) {
	streamTestEnvironment(t)
	for _, args := range [][]string{
		{"run", ".", "--llm-stream", "--llm-transport", "responses"},
		{"run", ".", "--llm-stream", "--llm-provider", "glm"},
		{"report", "--run-dir", "run", "--llm-stream", "--llm-transport", "responses"},
		{"expert", "--run-dir", "run", "--llm-stream", "--llm-provider", "glm"},
	} {
		if _, err := Parse(args); err == nil || !strings.Contains(err.Error(), "streaming requires") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	cfg := Config{LLMProvider: "deepseek", LLMStream: true, LLMAPIKey: "test"}.WithLLMProviderDefaults()
	if err := validateProviderConfig(cfg, "test"); err != nil {
		t.Fatalf("DeepSeek chat streaming: %v", err)
	}
}
