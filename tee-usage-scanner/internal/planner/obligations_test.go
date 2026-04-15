package planner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestLoadObligations_EmptyRoot(t *testing.T) {
	if got := planner.LoadObligations(""); got != "" {
		t.Errorf("expected empty string for empty root, got %q", got)
	}
}

func TestLoadObligations_MissingDir(t *testing.T) {
	dir := t.TempDir()
	if got := planner.LoadObligations(dir); got != "" {
		t.Errorf("expected empty string when wiki dirs don't exist, got %q", got)
	}
}

func TestLoadObligations_ReadsObligationsAndPatterns(t *testing.T) {
	root := t.TempDir()
	obligationsDir := filepath.Join(root, "wiki", "obligations")
	patternsDir := filepath.Join(root, "wiki", "patterns")
	if err := os.MkdirAll(obligationsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(patternsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(obligationsDir, "attestation.md"),
		[]byte("# Attestation\nVerify identity."), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(patternsDir, "caller-binding.md"),
		[]byte("# Caller Binding\nBind session to caller."), 0o644); err != nil {
		t.Fatal(err)
	}

	got := planner.LoadObligations(root)
	if !strings.Contains(got, "### attestation") {
		t.Error("missing obligations entry header")
	}
	if !strings.Contains(got, "Verify identity") {
		t.Error("missing obligations body")
	}
	if !strings.Contains(got, "### caller-binding") {
		t.Error("missing patterns entry header")
	}
	if !strings.Contains(got, "Bind session to caller") {
		t.Error("missing patterns body")
	}
}

func TestLoadObligations_SkipsEmptyFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "wiki", "obligations")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.md"), []byte("   \n\t"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := planner.LoadObligations(root); got != "" {
		t.Errorf("expected empty string when all files are blank, got %q", got)
	}
}
