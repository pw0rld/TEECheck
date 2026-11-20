package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/runbundle"
)

func writeValidatedFindings(t *testing.T, root, caseID, variant string, findings []teecheckFinding) {
	t.Helper()
	variantRoot := filepath.Join(root, caseID, variant)
	attemptID := "fixture-attempt"
	attemptRoot := filepath.Join(variantRoot, "attempts", attemptID)
	dir := filepath.Join(attemptRoot, "scan")
	runID := caseID + "-" + variant
	stages := []string{"preprocess", "repo_index", "project_map", "l3_planner", "cases_enrich", "expert", "challenger", "verifier", "arbiter"}
	repository, revision := "", ""
	if c, err := loadCase(filepath.Join("..", "..", "datasets", caseID)); err == nil {
		repository = c.Case.Repository
		revision = c.Case.VulnerableRevision
		if variant == "fixed" {
			revision = c.Oracle.FixedRevision
		}
	}
	write := func(path string, value any) {
		t.Helper()
		if err := writeJSONAtomic(filepath.Join(dir, path), value); err != nil {
			t.Fatal(err)
		}
	}
	write("00_manifest.json", map[string]any{"schema_version": "teecheck.manifest.v1", "run_id": runID, "repo_url": repository, "commit": revision, "local_path": dir, "created_at": time.Now().UTC().Format(time.RFC3339), "source_scope_mode": "local_fallback", "expected_stages": stages, "configuration": map[string]any{"command": "run", "mode": "llm", "samples": 1, "enable_legacy_prior": false}})
	for _, path := range []string{"01_context/repo_facts.v1.json", "01_context/project_map.v1.json", "04_planner/evidence_bundle.json"} {
		write(path, map[string]any{"run_id": runID})
	}
	for _, path := range []string{"03_cases", "04_expert", "05_challenger", "06_verifier"} {
		if err := os.MkdirAll(filepath.Join(dir, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write("04_planner/coverage_ledger.json", map[string]any{"schema_version": "teecheck.coverage_ledger.v1", "run_id": runID, "by_sample": []any{map[string]any{"sample_index": 0, "recon_status": "satisfied"}}})
	if findings == nil {
		findings = []teecheckFinding{}
	}
	for i := range findings {
		if findings[i].SliceID == "" {
			findings[i].SliceID = findings[i].FindingID
		}
		if findings[i].Severity == "" {
			findings[i].Severity = "medium"
		}
		if findings[i].Confidence == "" {
			findings[i].Confidence = "medium"
		}
		if findings[i].Summary == "" {
			findings[i].Summary = "fixture finding"
		}
	}
	write("07_arbiter/findings.json", teecheckFindings{SchemaVersion: "teecheck.findings.v2", RunID: runID, Findings: findings})
	all := []map[string]any{{"seq": 1, "type": "run_started", "run_id": runID}}
	for _, stage := range stages {
		all = append(all, map[string]any{"seq": len(all) + 1, "type": "stage_started", "run_id": runID, "stage": stage})
		all = append(all, map[string]any{"seq": len(all) + 1, "type": "stage_completed", "run_id": runID, "stage": stage, "reason": "completed"})
	}
	all = append(all, map[string]any{"seq": len(all) + 1, "type": "run_completed", "run_id": runID, "reason": "completed"})
	f, err := os.Create(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range all {
		b, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	validation := runbundle.Validate(dir)
	if !validation.Valid {
		t.Fatalf("invalid fixture bundle: %+v", validation.Issues)
	}
	record := attemptRecord{Schema: "teecheck.benchmark.attempt.v1", AttemptID: attemptID, CaseID: caseID, Variant: variant, StartedAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "completed", ExitCode: 0, BundlePath: "scan", Validation: &validation}
	if err := writeJSONAtomic(filepath.Join(attemptRoot, "attempt.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(filepath.Join(variantRoot, "latest.json"), latestAttempt{attemptID}); err != nil {
		t.Fatal(err)
	}
}
