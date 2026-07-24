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

func TestRegistry_DispatchesKnownAction(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn a() {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage(`{"path": ".", "depth": 1}`),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "a.rs") {
		t.Fatalf("expected a.rs in output, got: %s", result.Output)
	}
}

func TestRegistry_UnknownAction(t *testing.T) {
	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "nonexistent",
		Args:     json.RawMessage("{}"),
		RepoRoot: t.TempDir(),
	})
	if result.OK {
		t.Fatal("expected failure for unknown action")
	}
	if !strings.Contains(result.Error, "unknown action") {
		t.Fatalf("expected unknown action error, got: %s", result.Error)
	}
}

func TestRegistry_DurationRecorded(t *testing.T) {
	dir := t.TempDir()
	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage(`{"path": ".", "depth": 0}`),
		RepoRoot: dir,
	})
	if result.DurationMs < 0 {
		t.Fatalf("expected non-negative duration, got %d", result.DurationMs)
	}
}

func TestRegistry_NameIsBackfilled(t *testing.T) {
	reg := actions.NewDefaultRegistry()
	result := reg.Run(context.Background(), actions.ActionRequest{
		Name:     "list_dir",
		Args:     json.RawMessage(`{"path": "."}`),
		RepoRoot: t.TempDir(),
	})
	if result.Name != "list_dir" {
		t.Fatalf("expected name=list_dir, got %s", result.Name)
	}
}

func TestRegistry_ListsRegisteredActions(t *testing.T) {
	reg := actions.NewDefaultRegistry()
	names := reg.Names()
	want := map[string]bool{"list_dir": true, "read_file": true, "ripgrep": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) > 0 {
		t.Fatalf("registry missing handlers: %v", want)
	}
}

func TestNavRegistry_NoSinkAction(t *testing.T) {
	r := actions.NewDefaultRegistryWithNav()
	names := r.Names()
	for _, n := range names {
		if n == "sink_catalog_lookup" {
			t.Fatalf("sink_catalog_lookup must not be registered")
		}
	}
	want := []string{"done", "list_dir", "read_file", "reverse_trace", "ripgrep", "tree_sitter_outline"}
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
			}
		}
		if !found {
			t.Errorf("expected action %q registered, got %v", w, names)
		}
	}
}
