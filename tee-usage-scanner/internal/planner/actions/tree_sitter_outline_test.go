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
		"use_declaration",
		"foreign_mod_item",
		"function_item",
		"verify_quote",
		"safe_helper",
		"struct_item",
		"AttestationVerifier",
		"impl_item",
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
		t.Fatal("expected failure for non-Rust file")
	}
	if !strings.Contains(result.Error, "rust") && !strings.Contains(result.Error, ".rs") {
		t.Fatalf("expected rust extension error, got: %s", result.Error)
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
