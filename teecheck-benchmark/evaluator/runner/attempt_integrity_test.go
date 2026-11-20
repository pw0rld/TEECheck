package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCoverageForTest(t *testing.T, root, status string) {
	t.Helper()
	findings, err := findFindings(root)
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Dir(filepath.Dir(findings))
	dir := filepath.Join(runDir, "04_planner")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"schema_version": "teecheck.coverage_ledger.v1", "run_id": "case-1-fixed", "by_sample": []any{map[string]any{"sample_index": 0, "recon_status": status}}})
	if err := os.WriteFile(filepath.Join(dir, "coverage_ledger.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestScore_LegacyFindingsAreNotValidated(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "07_arbiter"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "07_arbiter", "findings.json"), []byte(`{"findings":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	score, err := scoreVariant(loadedCase{Case: caseSpec{ID: "old"}}, "fixed", dir)
	if err != nil || score.Classification != "ERROR" {
		t.Fatalf("legacy file was credited: %+v, %v", score, err)
	}
}

func TestEvaluate_NonzeroExitWithValidArtifactsStillError(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}}
	fixture := t.TempDir()
	writeFindings(t, fixture, c.Case.ID, "fixed", nil)
	source := filepath.Join(fixture, c.Case.ID, "fixed", "attempts", "fixture-attempt", "scan")
	root := t.TempDir()
	command := fmt.Sprintf("cp -R %s {run_dir}/scan; exit 9", shellQuote(source))
	if err := runScannerAttempt(c, "fixed", root, command, time.Second); err != nil {
		t.Fatal(err)
	}
	score, err := scoreVariant(c, "fixed", root)
	if err != nil || score.Classification != "ERROR" {
		t.Fatalf("nonzero exit with a valid bundle was accepted: %+v, %v", score, err)
	}
}

func TestScore_RevalidatesAttemptArtifacts(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}}
	root := t.TempDir()
	writeFindings(t, root, c.Case.ID, "fixed", nil)
	dir := filepath.Join(root, c.Case.ID, "fixed")
	path := filepath.Join(dir, "attempts", "fixture-attempt", "scan", "events.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	score, err := scoreVariant(c, "fixed", dir)
	if err != nil || score.Classification != "ERROR" {
		t.Fatalf("post-validation artifact corruption accepted: %+v, %v", score, err)
	}
}

func TestIncompleteCoverageIsNotAConfusionMatrixVerdict(t *testing.T) {
	metrics := trackMetrics{}
	metrics.add(caseScore{Vulnerable: variantScore{Classification: "INCOMPLETE_COVERAGE"}, Fixed: variantScore{Classification: "INCOMPLETE_COVERAGE"}})
	if metrics.Totals != (scoreTotals{}) || metrics.IncompleteCoverage != 1 {
		t.Fatalf("coverage gap counted as a detector verdict: %+v", metrics)
	}
}

func TestScore_RejectsOldManifestCopiedIntoNewAttempt(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}}
	root := t.TempDir()
	writeFindings(t, root, c.Case.ID, "fixed", nil)
	dir := filepath.Join(root, c.Case.ID, "fixed")
	path := filepath.Join(dir, "attempts", "fixture-attempt", "scan", "00_manifest.json")
	var m map[string]any
	if err := readJSON(path, &m); err != nil {
		t.Fatal(err)
	}
	m["created_at"] = "2000-01-01T00:00:00Z"
	if err := writeJSONAtomic(path, m); err != nil {
		t.Fatal(err)
	}
	score, err := scoreVariant(c, "fixed", dir)
	if err != nil || score.Classification != "ERROR" {
		t.Fatalf("old copied artifact accepted: %+v, %v", score, err)
	}
}

func TestScoreSeparatesPlannerAndDeterministicOrigins(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}, Oracle: oracleSpec{PrimaryFile: "a.c"}}
	root := t.TempDir()
	writeFindings(t, root, c.Case.ID, "vulnerable", []teecheckFinding{
		{FindingID: "det", Origin: "deterministic", Status: "likely_issue", Files: []string{"a.c"}},
		{FindingID: "planner", Origin: "planner", Status: "likely_issue", Files: []string{"other.c"}},
		{FindingID: "legacy", Status: "likely_issue", Files: []string{"unknown.c"}},
	})
	score, err := scoreVariant(c, "vulnerable", filepath.Join(root, c.Case.ID, "vulnerable"))
	if err != nil {
		t.Fatal(err)
	}
	if score.TargetOriginCounts["deterministic"] != 1 || score.TargetOriginCounts["planner"] != 0 || score.OriginCounts["planner"] != 1 || score.OriginCounts["unknown"] != 1 {
		t.Fatalf("origins conflated: %+v", score)
	}
}

func TestAttemptDoesNotTreatSourceExamplesAsItsOutput(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scan", "source", "examples", "old", "07_arbiter"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "scan", "00_manifest.json"), filepath.Join(root, "scan", "source", "examples", "old", "00_manifest.json"), filepath.Join(root, "scan", "source", "examples", "old", "07_arbiter", "findings.json")} {
		if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := findRunBundle(root); err == nil {
		t.Fatalf("source fixture mistaken for current output: %s", got)
	}
}

func TestEvaluate_FailedRunWithStaleFindingsScoresError(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}, Oracle: oracleSpec{PrimaryFile: "a.c"}}
	root := t.TempDir()
	for _, variant := range []string{"vulnerable", "fixed"} {
		writeFindings(t, root, c.Case.ID, variant, nil)
	}
	if err := evaluate([]loadedCase{c}, root, "exit 17", time.Second); err != nil {
		t.Fatal(err)
	}
	score, err := scoreVariant(c, "fixed", filepath.Join(root, c.Case.ID, "fixed"))
	if err != nil {
		t.Fatal(err)
	}
	if score.Classification != "ERROR" {
		t.Fatalf("failed scanner reused stale findings: %+v", score)
	}
}

func TestEvaluate_IncompleteReconZeroFindingsIsNotCleanTN(t *testing.T) {
	c := loadedCase{Case: caseSpec{ID: "case-1"}, Oracle: oracleSpec{PrimaryFile: "a.c"}}
	root := t.TempDir()
	writeFindings(t, root, c.Case.ID, "fixed", nil)
	dir := filepath.Join(root, c.Case.ID, "fixed")
	writeCoverageForTest(t, dir, "budget_exhausted")
	score, err := scoreVariant(c, "fixed", dir)
	if err != nil {
		t.Fatal(err)
	}
	if score.Classification != "INCOMPLETE_COVERAGE" {
		t.Fatalf("unfinished reconnaissance credited as clean: %+v", score)
	}
}
