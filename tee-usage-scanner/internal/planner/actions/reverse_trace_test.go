package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func reverseTraceArgs(t *testing.T, file, symbol string, depth int) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"file":   file,
		"symbol": symbol,
		"depth":  depth,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeSourceFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Helper: returns (repoRoot) with a known 3-level call chain:
//
//   attest.rs::target_fn     — the symbol being traced
//     ↓ called by
//   caller_a.rs::caller_a    — first-level caller
//     ↓ called by
//   caller_b.rs::caller_b    — second-level caller
//
// Plus an unrelated.rs file to verify filtering.
func setupCallChainFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeSourceFile(t, dir, "src/attest.rs", `
pub fn target_fn(quote: &[u8]) -> Result<(), Error> {
    Ok(())
}
`)
	writeSourceFile(t, dir, "src/caller_a.rs", `
use crate::attest::target_fn;

pub fn caller_a(data: &[u8]) -> Result<(), Error> {
    // calls the target
    target_fn(data)
}
`)
	writeSourceFile(t, dir, "src/caller_b.rs", `
use crate::caller_a::caller_a;

pub fn caller_b() -> Result<(), Error> {
    let data = &[0u8; 4];
    caller_a(data)?;
    Ok(())
}
`)
	writeSourceFile(t, dir, "src/unrelated.rs", `
pub fn unrelated_fn() -> u32 {
    42
}
`)
	return dir
}

func TestReverseTrace_FindsDirectCaller(t *testing.T) {
	dir := setupCallChainFixture(t)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/attest.rs", "target_fn", 1),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected: %s", result.Error)
	}
	if !strings.Contains(result.Output, "target_fn") {
		t.Errorf("output should name target_fn, got:\n%s", result.Output)
	}
	// caller_a must appear (direct caller)
	if !strings.Contains(result.Output, "caller_a") {
		t.Errorf("output should mention caller_a as direct caller, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "caller_a.rs") {
		t.Errorf("output should include caller_a.rs file path, got:\n%s", result.Output)
	}
	// With depth=1, caller_b should NOT appear
	if strings.Contains(result.Output, "caller_b") {
		t.Errorf("depth=1 should not reach caller_b, got:\n%s", result.Output)
	}
}

func TestReverseTrace_WalksUpMultipleDepths(t *testing.T) {
	dir := setupCallChainFixture(t)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/attest.rs", "target_fn", 2),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected: %s", result.Error)
	}
	// depth=2: should see both caller_a AND caller_b (through caller_a)
	if !strings.Contains(result.Output, "caller_a") {
		t.Errorf("depth=2 should include caller_a, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "caller_b") {
		t.Errorf("depth=2 should include caller_b via caller_a, got:\n%s", result.Output)
	}
}

func TestReverseTrace_UnrelatedFileExcluded(t *testing.T) {
	dir := setupCallChainFixture(t)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/attest.rs", "target_fn", 2),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected: %s", result.Error)
	}
	if strings.Contains(result.Output, "unrelated_fn") || strings.Contains(result.Output, "unrelated.rs") {
		t.Errorf("output should NOT include unrelated.rs, got:\n%s", result.Output)
	}
}

func TestReverseTrace_NoCallersReported(t *testing.T) {
	dir := t.TempDir()
	writeSourceFile(t, dir, "src/only.rs", `
pub fn lonely_fn() -> u32 {
    42
}
`)
	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/only.rs", "lonely_fn", 2),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected: %s", result.Error)
	}
	// Should mention the target but report 0 callers
	if !strings.Contains(result.Output, "lonely_fn") {
		t.Errorf("output should mention target, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "no callers") && !strings.Contains(result.Output, "0 callers") {
		t.Errorf("output should note zero callers, got:\n%s", result.Output)
	}
}

func TestReverseTrace_RejectsNonRustTarget(t *testing.T) {
	dir := t.TempDir()
	writeSourceFile(t, dir, "src/foo.py", `def target(): pass`)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/foo.py", "target", 1),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for non-Rust target file")
	}
}

func TestReverseTrace_RejectsMissingSymbol(t *testing.T) {
	dir := t.TempDir()
	writeSourceFile(t, dir, "src/x.rs", `pub fn foo() {}`)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/x.rs", "", 1),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for empty symbol")
	}
}

func TestReverseTrace_DepthClampedToMax(t *testing.T) {
	// Excessive depth should clamp to an internal max; the test just
	// verifies the handler does not recurse forever or panic.
	dir := setupCallChainFixture(t)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/attest.rs", "target_fn", 99),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected: %s", result.Error)
	}
	// Still includes the known chain nodes
	if !strings.Contains(result.Output, "caller_a") || !strings.Contains(result.Output, "caller_b") {
		t.Errorf("expected full chain, got:\n%s", result.Output)
	}
}

func TestReverseTrace_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "../outside.rs", "foo", 1),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}

func TestReverseTrace_LineNumbersIncluded(t *testing.T) {
	dir := setupCallChainFixture(t)

	h := actions.ReverseTraceHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "reverse_trace",
		Args:     reverseTraceArgs(t, "src/attest.rs", "target_fn", 1),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("error: %s", result.Error)
	}
	// Output should include a line annotation (":N:") for the caller site
	if !strings.Contains(result.Output, ":") {
		t.Errorf("expected line annotations, got: %s", result.Output)
	}
}

func TestReverseTrace_C(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "core.c"),
		[]byte("void verify(void) {}\n\nvoid caller(void)\n{\n    verify();\n}\n"), 0o644)
	res := actions.ReverseTraceHandler{}.Run(context.Background(), actions.ActionRequest{
		RepoRoot: dir, Args: reverseTraceArgs(t, "core.c", "verify", 1),
	})
	if !res.OK {
		t.Fatalf("expected OK, got: %s", res.Error)
	}
	if !strings.Contains(res.Output, "caller") {
		t.Errorf("expected caller in trace:\n%s", res.Output)
	}
}
