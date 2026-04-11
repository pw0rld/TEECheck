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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func listDirArgs(t *testing.T, path string, depth int) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"path": path, "depth": depth})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestListDir_HappyPath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.rs"), "fn a() {}")
	writeFile(t, filepath.Join(dir, "sub", "b.rs"), "fn b() {}")

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, ".", 2),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "sub") {
		t.Fatalf("expected sub in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "b.rs") {
		t.Fatalf("expected b.rs in output, got: %s", result.Output)
	}
}

func TestListDir_DepthZero(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.rs"), "")
	writeFile(t, filepath.Join(dir, "sub", "b.rs"), "")

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, ".", 0),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "b.rs") {
		t.Fatalf("depth=0 should not descend into sub, got: %s", result.Output)
	}
}

func TestListDir_DepthCappedAtThree(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "l1", "l2", "l3", "l4", "l5")
	writeFile(t, filepath.Join(deep, "leaf.rs"), "")

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, ".", 99),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "l3") {
		t.Fatalf("expected l3 in output, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "l5") {
		t.Fatalf("depth should cap at 3, but found l5: %s", result.Output)
	}
}

func TestListDir_EscapeRejected(t *testing.T) {
	dir := t.TempDir()

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     listDirArgs(t, "../../etc", 1),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
	if !strings.Contains(result.Error, "escape") {
		t.Fatalf("expected escape error, got: %s", result.Error)
	}
}

func TestListDir_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	h := actions.ListDirHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage("not json"),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for invalid json")
	}
	if !strings.Contains(result.Error, "invalid args") {
		t.Fatalf("expected invalid args error, got: %s", result.Error)
	}
}
