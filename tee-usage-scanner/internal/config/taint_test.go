package config

import (
	"testing"
	"time"
)

func TestParseTaintBudgetDefaultsAndOverrides(t *testing.T) {
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	for _, command := range []string{"run", "plan"} {
		t.Run(command, func(t *testing.T) {
			cfg, err := Parse([]string{command, "."})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MaxTaintQueries != 8 || cfg.MaxTaintQueriesExplicit || cfg.TaintQueryTimeout != 90*time.Second {
				t.Fatalf("wrong taint defaults: quota=%d explicit=%t timeout=%v", cfg.MaxTaintQueries, cfg.MaxTaintQueriesExplicit, cfg.TaintQueryTimeout)
			}
			cfg, err = Parse([]string{command, ".", "--max-taint-queries", "0", "--taint-query-timeout", "2m"})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MaxTaintQueries != 0 || !cfg.MaxTaintQueriesExplicit || cfg.TaintQueryTimeout != 2*time.Minute {
				t.Fatalf("explicit override lost: quota=%d explicit=%t timeout=%v", cfg.MaxTaintQueries, cfg.MaxTaintQueriesExplicit, cfg.TaintQueryTimeout)
			}
		})
	}
}

func TestParseTaintBudgetRejectsInvalidControls(t *testing.T) {
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	for _, flags := range [][]string{
		{"--max-taint-queries=-1"},
		{"--taint-query-timeout=0s"},
		{"--taint-query-timeout=-1s"},
		{"--taint-query-timeout=invalid"},
	} {
		if _, err := Parse(append([]string{"run", "."}, flags...)); err == nil {
			t.Fatalf("invalid taint controls accepted: %v", flags)
		}
	}
}
