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

func readFileArgs(t *testing.T, path string, start, end int) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"path": path, "start": start, "end": end})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadFile_FullSmallFile(t *testing.T) {
	dir := t.TempDir()
	content := "line 1\nline 2\nline 3\n"
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "f.txt", 1, 10),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "1: line 1") {
		t.Fatalf("expected line 1 prefix, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3: line 3") {
		t.Fatalf("expected line 3 prefix, got: %s", result.Output)
	}
}

func TestReadFile_PartialRange(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 1; i <= 100; i++ {
		lines = append(lines, strings.Repeat("x", 5))
	}
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "big.txt", 10, 12),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "10:") || !strings.Contains(result.Output, "12:") {
		t.Fatalf("expected lines 10..12, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "9:") || strings.Contains(result.Output, "13:") {
		t.Fatalf("expected only lines 10..12, got extras: %s", result.Output)
	}
}

func TestReadFile_LineCapEnforced(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("x\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "huge.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "huge.txt", 1, 0),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !result.Truncated {
		t.Fatal("expected truncated=true")
	}
	lineCount := strings.Count(result.Output, "\n")
	if lineCount > 500 {
		t.Fatalf("expected <=500 lines, got %d", lineCount)
	}
	if lineCount < 500 {
		t.Fatalf("expected 500 lines at cap, got %d", lineCount)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	dir := t.TempDir()

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "nope.txt", 1, 10),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for missing file")
	}
}

func TestReadFile_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.ReadFileHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "read_file",
		Args:     readFileArgs(t, "../secret.txt", 1, 10),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}
