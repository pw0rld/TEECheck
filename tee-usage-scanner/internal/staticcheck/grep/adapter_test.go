package grep_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/grep"
)

func TestGrepAdapterFindsKeywords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sample.rs"), []byte("fn verify_quote() {\n    // TODO check freshness\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := grep.New()
	if a.Name() != "grep" {
		t.Fatalf("expected name grep, got %s", a.Name())
	}
	if !a.Available() {
		t.Fatal("expected grep to be available")
	}

	findings, err := a.Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot:    dir,
		TargetFiles: []string{"sample.rs"},
		Keywords:    []string{"todo", "verify"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if f.ToolName != "grep" {
			t.Fatalf("expected tool_name grep, got %s", f.ToolName)
		}
	}
}

func TestGrepAdapterNoResults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.rs"), []byte("fn safe() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := grep.New()
	findings, err := a.Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot:    dir,
		TargetFiles: []string{"clean.rs"},
		Keywords:    []string{"vulnerability"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
