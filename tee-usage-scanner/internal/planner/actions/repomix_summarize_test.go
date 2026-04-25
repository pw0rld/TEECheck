package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func requireRepomix(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not installed; skipping repomix action tests")
	}
}

func repomixArgs(t *testing.T, path string, compress bool) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"path":     path,
		"compress": compress,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRepomixSummarize_HappyPath(t *testing.T) {
	requireRepomix(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn verify_quote() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, ".", false),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") && !strings.Contains(result.Output, "verify_quote") {
		t.Fatalf("output missing expected content: %s", result.Output)
	}
}

func TestRepomixSummarize_EscapeRejected(t *testing.T) {
	requireRepomix(t)
	dir := t.TempDir()

	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, "../../etc", false),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}

func TestRepomixSummarize_InvalidJSON(t *testing.T) {
	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     json.RawMessage("not json"),
		RepoRoot: t.TempDir(),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}

func TestRepomixSummarize_MissingNpx(t *testing.T) {
	if _, err := exec.LookPath("npx"); err == nil {
		t.Skip("npx is installed; cannot test missing-npx path")
	}
	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, ".", false),
		RepoRoot: t.TempDir(),
	})
	if result.OK {
		t.Fatal("expected failure when npx missing")
	}
}
