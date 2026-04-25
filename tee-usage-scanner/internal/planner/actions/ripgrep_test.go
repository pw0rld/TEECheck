package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// testExec is the bare LocalExecutor (no recorder, no blob store)
// used by the in-package ripgrep tests. Production wires a real
// executor via the pipeline; these tests exercise the handler logic
// in isolation.
func testExec() executor.Executor { return &executor.LocalExecutor{} }

func requireRipgrep(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg not installed; skipping ripgrep action tests")
	}
}

func ripgrepArgs(t *testing.T, pattern string, globs []string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pattern": pattern, "globs": globs})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRipgrep_FindsPattern(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn verify_quote() {}\nfn other() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote", nil),
		RepoRoot: dir,
		Executor: testExec(),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "verify_quote") {
		t.Fatalf("expected match, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected filename in output, got: %s", result.Output)
	}
}

func TestRipgrep_NoMatch(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn other() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote", nil),
		RepoRoot: dir,
		Executor: testExec(),
	})
	if !result.OK {
		t.Fatalf("expected OK on no-match, got error: %s", result.Error)
	}
	if strings.TrimSpace(result.Output) != "" {
		t.Fatalf("expected empty output, got: %s", result.Output)
	}
}

func TestRipgrep_GlobFilter(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("verify_quote\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.md"), []byte("verify_quote\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote", []string{"*.rs"}),
		RepoRoot: dir,
		Executor: testExec(),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs match, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "b.md") {
		t.Fatalf("glob filter should exclude b.md, got: %s", result.Output)
	}
}

func TestRipgrep_Truncation(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString("verify_quote_target\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "verify_quote_target", nil),
		RepoRoot: dir,
		Executor: testExec(),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !result.Truncated {
		t.Fatal("expected truncated=true for >200 matches")
	}
	got := strings.Count(result.Output, "\n")
	if got > 200 {
		t.Fatalf("expected <=200 lines after truncation, got %d", got)
	}
}

func TestRipgrep_MissingPattern(t *testing.T) {
	dir := t.TempDir()

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "", nil),
		RepoRoot: dir,
		Executor: testExec(),
	})
	if result.OK {
		t.Fatal("expected failure for empty pattern")
	}
	if !strings.Contains(result.Error, "pattern") {
		t.Fatalf("expected pattern error, got: %s", result.Error)
	}
}

// TestRipgrep_NoExecutorIsExplicitFailure verifies the handler does
// not silently fall back to an event-less executor when the request
// is missing one — that fallback would hide policy and observability
// from the run.
func TestRipgrep_NoExecutorIsExplicitFailure(t *testing.T) {
	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     ripgrepArgs(t, "x", nil),
		RepoRoot: t.TempDir(),
		// Executor intentionally nil
	})
	if result.OK {
		t.Fatal("expected failure when Executor is nil")
	}
	if !strings.Contains(result.Error, "executor") {
		t.Fatalf("expected error to mention executor wiring, got: %s", result.Error)
	}
}

// TestRipgrep_IsExecutorBacked confirms the handler advertises itself
// as executor-backed so the planner skips its manual emit path.
func TestRipgrep_IsExecutorBacked(t *testing.T) {
	h := actions.RipgrepHandler{}
	if !h.IsExecutorBacked() {
		t.Error("RipgrepHandler.IsExecutorBacked() = false, want true")
	}
}

// TestRegistry_IsExecutorBacked confirms the registry helper agrees
// with the handler's self-report and returns false for in-process
// actions and unknown names.
func TestRegistry_IsExecutorBacked(t *testing.T) {
	r := actions.NewDefaultRegistry()
	if !r.IsExecutorBacked("ripgrep") {
		t.Error("registry.IsExecutorBacked(ripgrep) = false, want true")
	}
	if r.IsExecutorBacked("read_file") {
		t.Error("registry.IsExecutorBacked(read_file) = true, want false (in-process action)")
	}
	if r.IsExecutorBacked("nonexistent") {
		t.Error("registry.IsExecutorBacked(nonexistent) = true, want false")
	}
}
