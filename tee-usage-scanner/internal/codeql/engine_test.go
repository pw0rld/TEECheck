package codeql

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEngineVersion(t *testing.T) {
	bin, _ := fakeCodeQL(t, `{"version":"2.24.0"}`, "", "", 0)
	e := NewWithBin(bin)

	got, err := e.Version(context.Background())
	if err != nil {
		t.Fatalf("Version returned error: %v", err)
	}
	if got != "2.24.0" {
		t.Fatalf("Version = %q, want 2.24.0", got)
	}
}

func TestEngineVersionRejectsMalformedOutput(t *testing.T) {
	bin, _ := fakeCodeQL(t, "not-json", "", "", 0)

	if _, err := NewWithBin(bin).Version(context.Background()); err == nil {
		t.Fatal("Version accepted malformed output")
	}
}

func TestAvailable(t *testing.T) {
	// Absolute path to an existing regular file → available.
	f := filepath.Join(t.TempDir(), "codeql")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !NewWithBin(f).Available() {
		t.Error("expected available for existing binary path")
	}
	// Absolute path to a nonexistent file → not available.
	if NewWithBin(filepath.Join(t.TempDir(), "nope")).Available() {
		t.Error("expected not available for missing binary")
	}
	// Absolute path to a directory → not available.
	if NewWithBin(t.TempDir()).Available() {
		t.Error("expected not available for a directory")
	}
}

func TestCreateAndAnalyzeGuardWhenUnavailable(t *testing.T) {
	e := NewWithBin(filepath.Join(t.TempDir(), "absent-codeql"))
	if err := e.CreateDatabase(context.Background(), CreateDBOptions{
		Language: "rust", SourceRoot: "/x", DBPath: "/y",
	}); err == nil {
		t.Error("CreateDatabase should error when codeql is unavailable")
	}
	if _, err := e.Analyze(context.Background(), AnalyzeOptions{
		DBPath: "/y", Queries: []string{"q.ql"},
	}); err == nil {
		t.Error("Analyze should error when codeql is unavailable")
	}
}

func TestCreateDatabaseValidatesArgs(t *testing.T) {
	// Use this test's own binary path so Available() is true, isolating the
	// argument validation from availability.
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve test executable")
	}
	e := NewWithBin(self)
	if err := e.CreateDatabase(context.Background(), CreateDBOptions{Language: "rust"}); err == nil {
		t.Error("expected error when source root and db path are missing")
	}
}
