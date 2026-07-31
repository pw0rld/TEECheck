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
	// "Searched and found nothing" must be a statement, not an absence. This
	// assertion used to require an empty Output; the round observation drops
	// an empty output field entirely (omitempty), so the model saw ok=true
	// and nothing else — indistinguishable from a tool that ran and reported
	// nothing for some other reason. On 2026-07-30 the CVE-2026-44362
	// vulnerable-side run read exactly that shape as "no rollback protection
	// here" and moved on.
	if !strings.Contains(result.Output, actions.RipgrepNoMatchOutput) {
		t.Fatalf("no-match Output = %q, want it to state %q", result.Output, actions.RipgrepNoMatchOutput)
	}
}

// A glob naming a directory must actually filter to that directory. The
// handler passed RepoRoot as an absolute search path, so ripgrep matched
// globs against absolute candidate paths and any glob containing a separator
// could never match — while a bare "*.rs" kept working because ripgrep
// matches those against the basename. Reproduced on 2026-07-30: the
// vulnerable-side round-4 search for version/rollback across
// core/crypto/*.c, core/kernel/*.c and core/tee/*.c returned exit 1 on a
// tree that did contain the file.
func TestRipgrep_PathQualifiedGlobMatches(t *testing.T) {
	requireRipgrep(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "core", "crypto"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "core", "crypto", "signed_hdr.c"), []byte("subkey_version\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "elsewhere.c"), []byte("subkey_version\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "ripgrep",
		// Two globs, only one of which has a matching directory — the exact
		// shape of the call that silently returned nothing.
		Args:     ripgrepArgs(t, "subkey_version", []string{"core/crypto/*.c", "core/kernel/*.c"}),
		RepoRoot: dir,
		Executor: testExec(),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "signed_hdr.c") {
		t.Fatalf("path-qualified glob found nothing; Output = %q", result.Output)
	}
	if strings.Contains(result.Output, "elsewhere.c") {
		t.Fatalf("glob must still exclude files outside it; Output = %q", result.Output)
	}
	// trackObservedPaths (internal/planner) derives repo-relative paths with
	// filepath.Rel(repoRoot, ...), so the output must stay absolute.
	if !strings.HasPrefix(strings.TrimSpace(result.Output), "/") {
		t.Errorf("Output must remain absolute-pathed for trackObservedPaths: %q", result.Output)
	}
}

// An argument the handler does not understand must be rejected, naming what
// is legal. ripgrepArgs declares only pattern and globs, so json.Unmarshal
// silently discarded everything else: the same 2026-07-30 run sent
// "i": true (case-insensitive) and "path": "core" on two separate rounds and
// neither reached rg, nor was either reported. A silently narrower search
// than the model asked for is worse than a rejected one — it cannot correct
// what it does not know was dropped.
func TestRipgrep_UnknownArgIsRejectedWithTheLegalNames(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"pattern": "x", "globs": []string{"*.c"}, "i": true})
	if err != nil {
		t.Fatal(err)
	}
	h := actions.RipgrepHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "ripgrep",
		Args:     raw,
		RepoRoot: t.TempDir(),
		Executor: testExec(),
	})
	if result.OK {
		t.Fatalf("unknown arg must fail the action, got OK with output %q", result.Output)
	}
	for _, want := range []string{"i", "pattern", "globs"} {
		if !strings.Contains(result.Error, want) {
			t.Errorf("error must name the offender and the legal args (missing %q): %s", want, result.Error)
		}
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
