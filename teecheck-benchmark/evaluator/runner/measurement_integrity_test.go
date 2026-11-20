package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchFindingRelatedTWEsAndPosition(t *testing.T) {
	var oracle oracleSpec
	if err := json.Unmarshal([]byte(`{"primary_file":"core/check.c","primary_line":120,"twe_family":"Guard","in_twe_scope":true}`), &oracle); err != nil {
		t.Fatal(err)
	}
	var finding teecheckFinding
	if err := json.Unmarshal([]byte(`{"finding_id":"opaque-case-17","related_twes":["TWE-GUARD-001"],"status":"likely_issue","files":["core/check.c"],"locations":[{"path":"core/check.c","start_line":126}]}`), &finding); err != nil {
		t.Fatal(err)
	}
	if ok, _ := matchFinding(oracle, finding); !ok {
		t.Fatal("explicit related_twes and nearby location must match without encoding class in finding_id")
	}
	finding.Locations[0].StartLine = 300
	if ok, _ := matchFinding(oracle, finding); ok {
		t.Fatal("same file and family at another site must not match")
	}
}

func TestMatchFindingUsesPrimarySymbols(t *testing.T) {
	var oracle oracleSpec
	_ = json.Unmarshal([]byte(`{"primary_file":"core/check.c","primary_symbols":["validate_quote"],"twe_family":"Guard","in_twe_scope":true}`), &oracle)
	var finding teecheckFinding
	_ = json.Unmarshal([]byte(`{"finding_id":"opaque","related_twes":["TWE-GUARD-001"],"status":"likely_issue","files":["core/check.c"],"locations":[{"path":"core/check.c","start_line":180,"symbol":"validate_quote"}]}`), &finding)
	if ok, _ := matchFinding(oracle, finding); !ok {
		t.Fatal("a primary symbol must match when the oracle has no exact line")
	}
}

func TestScoreVariantReportsIncidentalFindings(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}, Oracle: oracleSpec{PrimaryFile: "target.c", TWEFamily: "Guard", InTWEScope: true}}
	root := t.TempDir()
	writeFindings(t, root, c.Case.ID, "fixed", []teecheckFinding{{FindingID: "TWE-GUARD-001:other", Status: "likely_issue", Files: []string{"other.c"}}})
	got, err := scoreVariant(c, "fixed", filepath.Join(root, c.Case.ID, "fixed"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	if fields["target_observed"] != false || fields["incidental_count"] != float64(1) {
		t.Fatalf("target-specific TN must expose its unrelated finding: %s", b)
	}
	if got.Observed != "incidental_only" {
		t.Fatalf("observed=%q hides unrelated finding", got.Observed)
	}
}

func TestScoreEmptyScopeWarns(t *testing.T) {
	r, err := buildScore(nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if text := renderMarkdown(r); !strings.Contains(text, "no classified in-scope cases") {
		t.Fatalf("empty capability track needs a visible warning: %s", text)
	}
}

func TestRepositoryOraclesHaveReviewedScopeAndLocation(t *testing.T) {
	for _, c := range loadRepositoryCases(t) {
		t.Run(c.Case.ID, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(c.Dir, "oracle.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var o map[string]any
			if err := json.Unmarshal(b, &o); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"twe_family", "in_twe_scope", "scope_reason", "primary_line", "primary_symbols"} {
				if _, ok := o[key]; !ok {
					t.Errorf("missing reviewed %s", key)
				}
			}
			if reason, _ := o["scope_reason"].(string); strings.TrimSpace(reason) == "" {
				t.Error("scope_reason must explain the source-backed decision")
			}
		})
	}
}

func TestPrimarySymbolDoesNotOverrideConflictingLine(t *testing.T) {
	var o oracleSpec
	_ = json.Unmarshal([]byte(`{"primary_file":"core/check.c","primary_line":120,"primary_symbols":["validate_quote"],"twe_family":"Guard"}`), &o)
	var f teecheckFinding
	_ = json.Unmarshal([]byte(`{"finding_id":"opaque","related_twes":["TWE-GUARD-001"],"status":"likely_issue","files":["core/check.c"],"locations":[{"path":"core/check.c","start_line":180,"symbol":"validate_quote"}]}`), &f)
	if ok, _ := matchFinding(o, f); ok {
		t.Fatal("same symbol cannot override a location outside the oracle tolerance")
	}
	f.Locations[0].StartLine = 0
	if ok, _ := matchFinding(o, f); !ok {
		t.Fatal("symbol is available as fallback when a source line is unavailable")
	}
}

func TestStrictScopeRejectsEmptyHeadlineTrack(t *testing.T) {
	if err := ensureInScope([]loadedCase{{Oracle: oracleSpec{}}}); err == nil {
		t.Fatal("strict mode must reject empty in-scope track")
	}
	if err := ensureInScope([]loadedCase{{Oracle: oracleSpec{InTWEScope: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := ensureInScope([]loadedCase{{Oracle: oracleSpec{InTWEScope: true, FixtureStatus: "requires_review"}}}); err == nil {
		t.Fatal("an unverified source pair must not populate the capability track")
	}
}

func TestExplicitWeaknessMetadataOverridesLegacyID(t *testing.T) {
	oracle := oracleSpec{PrimaryFile: "a.c", TWEFamily: "Guard", InTWEScope: true}
	finding := teecheckFinding{FindingID: "TWE-GUARD-001:old", RelatedTWEs: []string{"TWE-STATE-001"}, Status: "likely_issue", Files: []string{"a.c"}}
	if ok, _ := matchFinding(oracle, finding); ok {
		t.Fatal("legacy identifier must not override explicit nonmatching weakness metadata")
	}
}
