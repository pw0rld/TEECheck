package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
	scanall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner/all"
)

func TestScanHeuristic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "verify.rs"), []byte("pub fn verify_quote() {}\nfn check_policy() {}\npub struct Report {}\n"), 0o644)
	os.WriteFile(filepath.Join(src, "state.rs"), []byte("pub fn apply_transition() {}\n"), 0o644)

	reg := scanall.NewDefaultGraphRegistry()
	result, err := scanner.Scan(context.Background(), reg, scanner.ScanRequest{
		RepoRoot: dir,
		Mode:     "heuristic",
	})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Nodes) == 0 {
		t.Fatal("expected nodes")
	}
	if len(result.Edges) == 0 {
		t.Fatal("expected edges")
	}

	hasFile := false
	hasFunc := false
	for _, n := range result.Nodes {
		if n.Kind == "file" {
			hasFile = true
		}
		if n.Kind == "function" {
			hasFunc = true
		}
	}
	if !hasFile || !hasFunc {
		t.Fatalf("expected file and function nodes, got: %+v", result.Nodes)
	}
}
