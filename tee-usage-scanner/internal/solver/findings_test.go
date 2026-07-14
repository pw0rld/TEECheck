package solver

import (
	"encoding/json"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

func TestBuildFindings(t *testing.T) {
	results := []Result{
		{
			TWEID: "TWE-BIND-001", SiteID: "reg-42", Status: Confirmed,
			Reason:   "obligation missing",
			Evidence: []codeql.Result{{RuleID: "binding/missing", Path: "src/registry.rs", StartLine: 8, Level: "error"}},
		},
		{TWEID: "TWE-BIND-001", SiteID: "reg-99", Status: GuardedElsewhere, Reason: "no violation"},
	}
	doc := BuildFindings("run-1", results)

	if doc.SchemaVersion != "teecheck.findings.v2" || doc.RunID != "run-1" {
		t.Fatalf("doc header wrong: %+v", doc)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("findings=%d want 2", len(doc.Findings))
	}
	c := doc.Findings[0]
	if c.FindingID != "TWE-BIND-001:reg-42" || c.Status != "confirmed" || c.Confidence != "high" || c.Severity != "error" {
		t.Fatalf("confirmed finding wrong: %+v", c)
	}
	if len(c.Files) != 1 || c.Files[0] != "src/registry.rs" {
		t.Errorf("files=%v", c.Files)
	}
	// round-trips as JSON (shared artifact schema)
	if _, err := json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
}
