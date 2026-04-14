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

func legacyArgs(t *testing.T, runDir string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"run_dir": runDir})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// writeMinimalRunInputs prepares the manifest, profile, graph, and
// repo_map files that mapper + hotspots expect to read.
func writeMinimalRunInputs(t *testing.T) (runDir string) {
	t.Helper()
	runDir = t.TempDir()

	mustWriteJSON(t, filepath.Join(runDir, "00_manifest.json"), map[string]any{
		"schema_version": "teecheck.manifest.v1",
		"run_id":         "test-run",
		"repo_url":       "https://example.com/repo",
		"commit":         "deadbeef",
		"focus":          "tee",
		"created_at":     "2026-04-12T00:00:00Z",
	})

	mustWriteJSON(t, filepath.Join(runDir, "01_profile", "project_profile.json"), map[string]any{
		"schema_version": "teecheck.project_profile.v1",
		"run_id":         "test-run",
		"languages":      []string{"rust"},
	})

	// Minimal graph with a file + function node.
	mustWriteJSON(t, filepath.Join(runDir, "02_graph", "graph.json"), map[string]any{
		"nodes": []map[string]any{
			{
				"id":       "n1",
				"kind":     "file",
				"name":     "verify.rs",
				"path":     "src/attest/verify.rs",
				"language": "rust",
			},
			{
				"id":       "n2",
				"kind":     "function",
				"name":     "verify_quote",
				"path":     "src/attest/verify.rs",
				"language": "rust",
			},
		},
		"edges": []map[string]any{
			{"source": "n1", "target": "n2", "kind": "contains"},
		},
	})

	return runDir
}

func mustWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyKeywordScan_HappyPath(t *testing.T) {
	runDir := writeMinimalRunInputs(t)

	h := actions.LegacyKeywordScanHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "legacy_keyword_scan",
		Args: legacyArgs(t, runDir),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if !strings.Contains(result.Output, "hotspot") {
		t.Fatalf("output missing hotspot mention: %s", result.Output)
	}

	if _, err := os.Stat(filepath.Join(runDir, "02_hotspots", "hotspot_index.json")); err != nil {
		t.Fatalf("hotspot_index.json not written: %v", err)
	}
}

func TestLegacyKeywordScan_MissingRunDir(t *testing.T) {
	h := actions.LegacyKeywordScanHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "legacy_keyword_scan",
		Args: legacyArgs(t, "/nonexistent"),
	})
	if result.OK {
		t.Fatal("expected failure for missing run dir")
	}
}

func TestLegacyKeywordScan_InvalidJSON(t *testing.T) {
	h := actions.LegacyKeywordScanHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "legacy_keyword_scan",
		Args: json.RawMessage("not json"),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}
