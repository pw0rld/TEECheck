package config

import "testing"

func TestDeepSeekPresetUsesCurrentModelAndLegacyChatDefault(t *testing.T) {
	current := (Config{LLMProvider: "DeepSeek"}).WithLLMProviderDefaults()
	if current.LLMProvider != LLMProviderDeepSeek || current.LLMBaseURL != "https://api.deepseek.com/v1" || current.LLMTransport != LLMTransportChatCompletions || current.LLMModel != "deepseek-flash" || current.LLMMaxTokens != DefaultLLMMaxTokens {
		t.Fatalf("preset: %+v", current)
	}
	legacy := (Config{LLMProvider: LLMProviderDeepSeek, LLMModel: "deepseek-chat"}).WithLLMProviderDefaults()
	if legacy.LLMMaxTokens != 8192 || legacy.LLMModel != "deepseek-chat" {
		t.Fatalf("legacy model changed: %+v", legacy)
	}
	for _, budget := range []int{2048, 16384, 32768} {
		explicit := (Config{LLMProvider: LLMProviderDeepSeek, LLMModel: "deepseek-chat", LLMMaxTokens: budget, LLMMaxTokensExplicit: true}).WithLLMProviderDefaults()
		if explicit.LLMMaxTokens != budget {
			t.Fatalf("explicit %d changed to %d", budget, explicit.LLMMaxTokens)
		}
	}
	fromGlobalDefault := (Config{LLMProvider: LLMProviderDeepSeek, LLMModel: "deepseek-chat", LLMMaxTokens: DefaultLLMMaxTokens}).WithLLMProviderDefaults()
	if fromGlobalDefault.LLMMaxTokens != 8192 {
		t.Fatalf("inherited global default not adjusted: %d", fromGlobalDefault.LLMMaxTokens)
	}
}

func clearDeepSeekEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER", "TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL", "TEECHECK_LLM_API_KEY", "OPENAI_API_KEY", "TEECHECK_LLM_MODEL", "OPENAI_MODEL", "TEECHECK_LLM_MAX_TOKENS", "TEECHECK_ROLE_CONFIG", "TEECHECK_LLM_REASONING_EFFORT"} {
		t.Setenv(name, "")
	}
}

func TestDeepSeekLegacyDefaultRespectsCLIAndEnvironmentBudget(t *testing.T) {
	clearDeepSeekEnv(t)
	args := []string{"run", ".", "--llm-provider", "deepseek", "--llm-model", "deepseek-chat", "--llm-api-key", "test"}
	for _, tc := range []struct {
		name     string
		extra    []string
		env      string
		want     int
		explicit bool
	}{
		{"default", nil, "", 8192, false},
		{"CLI", []string{"--llm-max-tokens", "32768"}, "", 32768, true},
		{"environment", nil, "12000", 12000, true},
		{"CLI overrides environment", []string{"--llm-max-tokens", "7000"}, "12000", 7000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEECHECK_LLM_MAX_TOKENS", tc.env)
			cfg, err := Parse(append(append([]string{}, args...), tc.extra...))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LLMMaxTokens != tc.want || cfg.LLMMaxTokensExplicit != tc.explicit {
				t.Fatalf("budget=%d explicit=%v", cfg.LLMMaxTokens, cfg.LLMMaxTokensExplicit)
			}
		})
	}
}

func TestDeepSeekRoleDefaultsDoNotLeakBetweenModels(t *testing.T) {
	budget := 16000
	cfg := Config{LLMProvider: LLMProviderDeepSeek, LLMModel: "deepseek-chat", RoleOverrides: map[string]LLMRoleOverride{
		"planner": {Model: "deepseek-flash"}, "verifier": {MaxOutputTokens: &budget},
	}}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if roles["expert"].LLMMaxTokens != 8192 || roles["planner"].LLMMaxTokens != 32768 || roles["verifier"].LLMMaxTokens != 16000 {
		t.Fatalf("role budgets: expert=%d planner=%d verifier=%d", roles["expert"].LLMMaxTokens, roles["planner"].LLMMaxTokens, roles["verifier"].LLMMaxTokens)
	}
	copied := cfg.WithLLMProviderDefaults().WithLLMSettingsFrom(roles["verifier"]).WithLLMProviderDefaults()
	if copied.LLMMaxTokens != 16000 || !copied.LLMMaxTokensExplicit {
		t.Fatal("explicit role budget lost when applied to stage")
	}
	cfg.LLMMaxTokens = 5000
	roles, err = cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if roles["planner"].LLMMaxTokens != 5000 {
		t.Fatal("explicit global budget lost after role model change")
	}
}

func TestDeepSeekThinkingEffortUsesChatTransport(t *testing.T) {
	clearDeepSeekEnv(t)
	_, err := Parse([]string{"run", ".", "--llm-provider", "deepseek", "--llm-api-key", "test", "--llm-reasoning-effort", "max"})
	if err != nil {
		t.Fatal(err)
	}
	if DeepSeekThinkingModel("not-deepseek-reasoner") || DeepSeekThinkingModel("custom-reason-model") {
		t.Fatal("reasoning model detection is too broad")
	}
}
