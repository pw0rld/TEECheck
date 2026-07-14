package codeql

import (
	"os"
	"path/filepath"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestParseSARIFVulnerable parses the real SARIF the M2 spike produced for the
// vulnerable TWE-BIND-0001 crate: exactly one binding violation at the
// register_worker function.
func TestParseSARIFVulnerable(t *testing.T) {
	results, err := ParseSARIF(readTestdata(t, "binding_vulnerable.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%d want 1", len(results))
	}
	r := results[0]
	if r.RuleID != "teecheck/binding/missing-subject-binding" {
		t.Errorf("ruleID=%q", r.RuleID)
	}
	if r.Path != "src/registry.rs" {
		t.Errorf("path=%q", r.Path)
	}
	if r.StartLine != 8 {
		t.Errorf("startLine=%d want 8", r.StartLine)
	}
	if r.Message == "" {
		t.Error("message is empty")
	}
}

// TestParseSARIFFixed confirms the fixed variant yields zero findings — the
// discrimination that makes the deterministic spine worthwhile.
func TestParseSARIFFixed(t *testing.T) {
	results, err := ParseSARIF(readTestdata(t, "binding_fixed.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("results=%d want 0", len(results))
	}
}

func TestParseSARIFMalformed(t *testing.T) {
	if _, err := ParseSARIF([]byte("{not sarif")); err == nil {
		t.Fatal("expected parse error on malformed input")
	}
}

func TestParseSARIFEmptyRuns(t *testing.T) {
	results, err := ParseSARIF([]byte(`{"runs":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("results=%d want 0", len(results))
	}
}
