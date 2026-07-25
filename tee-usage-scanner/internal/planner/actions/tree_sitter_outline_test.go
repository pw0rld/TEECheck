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

func outlineArgs(t *testing.T, path string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const sampleRust = `use core::ffi::c_void;
use std::ptr;

extern "C" {
    fn sgx_create_report(p: *const u8) -> u32;
}

#[no_mangle]
pub unsafe fn verify_quote(quote: &[u8]) -> Result<(), Error> {
    Ok(())
}

pub fn safe_helper(x: u64) -> u64 {
    x + 1
}

pub struct AttestationVerifier {
    pub mr_enclave: [u8; 32],
}

impl AttestationVerifier {
    pub fn new() -> Self {
        Self { mr_enclave: [0; 32] }
    }
    pub fn verify(&self, quote: &[u8]) -> bool {
        true
    }
}
`

func TestTreeSitterOutline_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "attest.rs"), []byte(sampleRust), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "attest.rs"),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}

	wants := []string{
		"verify_quote",
		"safe_helper",
		"AttestationVerifier",
		"new",
		"verify",
	}
	for _, w := range wants {
		if !strings.Contains(result.Output, w) {
			t.Errorf("expected outline to mention %q, output:\n%s", w, result.Output)
		}
	}
}

func TestTreeSitterOutline_LineNumbersIncluded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte(sampleRust), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "a.rs"),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "line ") {
		t.Fatalf("expected line annotations, got: %s", result.Output)
	}
}

func TestTreeSitterOutline_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.rs"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "empty.rs"),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("error: %s", result.Error)
	}
}

func TestTreeSitterOutline_RejectsNonRust(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.py"), []byte("def x(): pass"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "f.py"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for non-source file")
	}
	if !strings.Contains(result.Error, "unsupported") {
		t.Fatalf("expected unsupported file type error, got: %s", result.Error)
	}
}

func TestTreeSitterOutline_NotFound(t *testing.T) {
	dir := t.TempDir()

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "missing.rs"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for missing file")
	}
}

func TestTreeSitterOutline_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.TreeSitterOutlineHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "tree_sitter_outline",
		Args:     outlineArgs(t, "../escape.rs"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}

func TestTreeSitterOutline_C(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ta.c")
	if err := os.WriteFile(path, []byte("TEE_Result handle_invoke(uint32_t cmd)\n{\n    return 0;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := actions.TreeSitterOutlineHandler{}.Run(context.Background(), actions.ActionRequest{RepoRoot: dir, Args: outlineArgs(t, "ta.c")})
	if !res.OK {
		t.Fatalf("expected OK, got error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "handle_invoke") {
		t.Errorf("C outline missing handle_invoke:\n%s", res.Output)
	}
}

func TestTreeSitterOutline_RejectsNonSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.toml")
	_ = os.WriteFile(path, []byte("[package]\n"), 0o644)
	res := actions.TreeSitterOutlineHandler{}.Run(context.Background(), actions.ActionRequest{RepoRoot: dir, Args: outlineArgs(t, "Cargo.toml")})
	if res.OK {
		t.Errorf("expected non-source file to be rejected")
	}
}
