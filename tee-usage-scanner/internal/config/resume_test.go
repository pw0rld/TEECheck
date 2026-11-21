package config

import "testing"

func TestResumeFlags(t *testing.T) {
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	for _, args := range [][]string{
		{"run", "--resume", "--run-dir", "runs/old"},
		{"run", "runs/old", "--resume"},
		{"run", "--resume", "runs/old"},
	} {
		cfg, err := Parse(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !cfg.Resume || cfg.RunDir != "runs/old" {
			t.Fatalf("%v: %+v", args, cfg)
		}
	}
	if _, err := Parse([]string{"run", "source", "--run-dir", "runs/old"}); err == nil {
		t.Fatal("run-dir without resume accepted")
	}
}
