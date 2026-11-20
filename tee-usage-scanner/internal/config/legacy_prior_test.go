package config

import "testing"

func TestParseRun_LegacyPriorIsOptIn(t *testing.T) {
	t.Setenv("TEECHECK_LLM_PROVIDER", "openai")
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	for _, command := range []string{"run", "plan"} {
		t.Run(command, func(t *testing.T) {
			cfg, err := Parse([]string{command, "."})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.EnableLegacyPrior {
				t.Fatal("legacy prior must be disabled by default")
			}
			cfg, err = Parse([]string{command, ".", "--enable-legacy-prior"})
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.EnableLegacyPrior {
				t.Fatal("explicit legacy opt-in was ignored")
			}
		})
	}
}
