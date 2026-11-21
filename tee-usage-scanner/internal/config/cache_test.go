package config

import "testing"

func TestRunCodeQLCacheConfiguration(t *testing.T) {
	t.Setenv("TEECHECK_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("TEECHECK_LLM_MODEL", "test-model")
	t.Setenv("TEECHECK_LLM_API_KEY", "test-key")
	t.Setenv("TEECHECK_CODEQL_CACHE_DIR", "")
	cfg, err := Parse([]string{"run", "."})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CodeQLCacheDir != "" {
		t.Fatal("shared cache should be opt-in")
	}
	t.Setenv("TEECHECK_CODEQL_CACHE_DIR", "/tmp/from-environment")
	cfg, err = Parse([]string{"run", "."})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CodeQLCacheDir != "/tmp/from-environment" {
		t.Fatalf("environment default=%q", cfg.CodeQLCacheDir)
	}
	cfg, err = Parse([]string{"run", ".", "--codeql-cache-dir", "/tmp/from-flag"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CodeQLCacheDir != "/tmp/from-flag" {
		t.Fatalf("flag override=%q", cfg.CodeQLCacheDir)
	}
}
