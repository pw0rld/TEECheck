package codeql

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssembleFixtureCrate(t *testing.T) {
	root := t.TempDir()
	harness := filepath.Join(root, "harness")
	variant := filepath.Join(root, "vulnerable")
	dest := filepath.Join(root, "crate")

	// harness skeleton with a stub + a placeholder scan file + a target/ dir
	// that must not be copied.
	mustWrite(t, filepath.Join(harness, "Cargo.toml"), "[package]\n")
	mustWrite(t, filepath.Join(harness, "src", "attest.rs"), "// stub\n")
	mustWrite(t, filepath.Join(harness, "src", "registry.rs"), "// placeholder\n")
	mustWrite(t, filepath.Join(harness, "target", "junk"), "BIG\n")
	// variant supplies the real scan file
	mustWrite(t, filepath.Join(variant, "src", "registry.rs"), "// real vulnerable code\n")

	if err := AssembleFixtureCrate(harness, variant, []string{"src/registry.rs"}, dest); err != nil {
		t.Fatal(err)
	}
	// harness files present
	if _, err := os.Stat(filepath.Join(dest, "Cargo.toml")); err != nil {
		t.Error("Cargo.toml not copied")
	}
	if _, err := os.Stat(filepath.Join(dest, "src", "attest.rs")); err != nil {
		t.Error("stub module not copied")
	}
	// target/ excluded
	if _, err := os.Stat(filepath.Join(dest, "target")); !os.IsNotExist(err) {
		t.Error("target/ should not be copied")
	}
	// scan file overlaid with the variant's content
	got, err := os.ReadFile(filepath.Join(dest, "src", "registry.rs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "// real vulnerable code\n" {
		t.Errorf("scan file not overlaid: %q", got)
	}
}

func TestRustLibrariesPathMissing(t *testing.T) {
	if _, err := RustLibrariesPath(t.TempDir()); err == nil {
		t.Fatal("expected error when no rust-queries cache is present")
	}
}

func TestRustLibrariesPathFound(t *testing.T) {
	root := t.TempDir()
	libs := filepath.Join(root, "qlpacks", "codeql", "rust-queries", "0.1.37", ".codeql", "libraries")
	if err := os.MkdirAll(libs, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := RustLibrariesPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != libs {
		t.Errorf("got %q want %q", got, libs)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
