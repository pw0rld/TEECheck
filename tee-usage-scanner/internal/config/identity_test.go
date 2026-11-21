package config

import "testing"

func TestParseSourceIdentityDefaultsAndOverrides(t *testing.T) {
	for _, command := range []string{"run", "plan"} {
		t.Run(command, func(t *testing.T) {
			t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
			t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
			t.Setenv("TEECHECK_LLM_MODEL", "test-model")
			t.Setenv("TEECHECK_REPO_URL", "https://example.test/upstream.git")
			t.Setenv("TEECHECK_COMMIT", "fixture-revision")

			cfg, err := Parse([]string{command, "./fixture"})
			if err != nil {
				t.Fatalf("Parse defaults: %v", err)
			}
			if cfg.Command != command || cfg.RepoURL != "https://example.test/upstream.git" || cfg.Commit != "fixture-revision" {
				t.Fatalf("unexpected source identity: command=%q repo=%q commit=%q", cfg.Command, cfg.RepoURL, cfg.Commit)
			}

			cfg, err = Parse([]string{command, "./fixture", "--repo-url", "https://example.test/explicit.git", "--commit", "explicit-revision"})
			if err != nil {
				t.Fatalf("Parse overrides: %v", err)
			}
			if cfg.RepoURL != "https://example.test/explicit.git" || cfg.Commit != "explicit-revision" {
				t.Fatalf("flags did not override environment: repo=%q commit=%q", cfg.RepoURL, cfg.Commit)
			}
		})
	}
}

func TestParseSourceIdentityUnsetPreservesDetection(t *testing.T) {
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	t.Setenv("TEECHECK_REPO_URL", "")
	t.Setenv("TEECHECK_COMMIT", "")
	for _, command := range []string{"run", "plan"} {
		cfg, err := Parse([]string{command, "./fixture"})
		if err != nil {
			t.Fatalf("Parse %s: %v", command, err)
		}
		if cfg.RepoURL != "" || cfg.Commit != "" {
			t.Fatalf("%s introduced identity without an override: repo=%q commit=%q", command, cfg.RepoURL, cfg.Commit)
		}
	}
}
