package semgrep

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

func TestParseSemgrepOutput(t *testing.T) {
	raw := []byte(`{
		"results": [
			{
				"check_id": "rules.tee.missing-attestation",
				"path": "src/verify.rs",
				"start": {"line": 42, "col": 1},
				"end": {"line": 42, "col": 30},
				"extra": {
					"message": "Missing attestation check",
					"severity": "WARNING",
					"lines": "    let quote = get_quote();"
				}
			}
		]
	}`)

	findings, err := parseSemgrepJSON(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ToolName != "semgrep" {
		t.Fatalf("expected tool_name semgrep, got %s", f.ToolName)
	}
	if f.RuleID != "rules.tee.missing-attestation" {
		t.Fatalf("unexpected rule_id: %s", f.RuleID)
	}
	if f.Path != "src/verify.rs" {
		t.Fatalf("unexpected path: %s", f.Path)
	}
	if f.StartLine != 42 {
		t.Fatalf("expected start_line 42, got %d", f.StartLine)
	}
	if f.Message != "Missing attestation check" {
		t.Fatalf("unexpected message: %s", f.Message)
	}
}

func TestParseSemgrepEmptyResults(t *testing.T) {
	raw := []byte(`{"results": []}`)
	findings, err := parseSemgrepJSON(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestAdapterName(t *testing.T) {
	a := New()
	if a.Name() != "semgrep" {
		t.Fatalf("expected name semgrep, got %s", a.Name())
	}
}

func TestAdapterAvailable(t *testing.T) {
	a := New()
	_ = a.Available() // just verify no panic
}

var _ staticcheck.Adapter = (*Adapter)(nil)
