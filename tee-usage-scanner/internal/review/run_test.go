package review_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestReviewFlow(t *testing.T) {
	runDir := t.TempDir()

	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-001",
		Findings: []artifacts.FindingItem{
			{
				FindingID:  "case-001",
				SliceID:    "case-001",
				Status:     "likely_issue",
				Severity:   "high",
				Confidence: "high",
				Files:      []string{"verify.rs"},
				Summary:    "Missing attestation",
			},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findings); err != nil {
		t.Fatal(err)
	}

	packetsDir := runfs.ArbiterPacketsDir(runDir)
	if err := os.MkdirAll(packetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packetsDir, "review-001.md"), []byte("# Review Packet: case-001\n\nSome content here.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Phase 1 prompt order:
	//   verdict, [fp_reason if FP], severity_override,
	//   confidence_override, tags, notes
	// Inputs: t (true_positive), keep severity, keep confidence,
	// tag "attestation", note "Looks real".
	input := "t\n\n\nattestation\nLooks real\n"
	var output bytes.Buffer

	cfg := config.Config{
		Command: "review",
		RunDir:  runDir,
	}
	now := time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC)
	err := review.RunWithIO(cfg, strings.NewReader(input), &output, now)
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}

	reviewPath := filepath.Join(runfs.ReviewDir(runDir), "review-001.json")
	data, err := os.ReadFile(reviewPath)
	if err != nil {
		t.Fatalf("review file not found: %v", err)
	}
	var rec artifacts.ReviewRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse review record: %v", err)
	}
	if rec.Verdict != artifacts.VerdictTruePositive {
		t.Fatalf("expected verdict %q, got %q", artifacts.VerdictTruePositive, rec.Verdict)
	}
	// Reviewer kept the arbiter's severity & confidence — both
	// override fields stay empty.
	if rec.CorrectedSeverity != "" {
		t.Errorf("CorrectedSeverity=%q want empty (kept arbiter value)", rec.CorrectedSeverity)
	}
	if rec.ConfidenceOverride != "" {
		t.Errorf("ConfidenceOverride=%q want empty (kept arbiter value)", rec.ConfidenceOverride)
	}
	if len(rec.Tags) != 1 || rec.Tags[0] != "attestation" {
		t.Fatalf("unexpected tags: %v", rec.Tags)
	}

	jsonlPath := runfs.ReviewRecordsPath(runDir)
	if _, err := os.Stat(jsonlPath); err != nil {
		t.Fatalf("review_records.jsonl not found: %v", err)
	}
}

// TestReviewFlow_FalsePositive exercises the FP branch: verdict =
// false_positive triggers the FP-reason prompt, severity gets
// corrected, notes capture the rationale.
func TestReviewFlow_FalsePositive(t *testing.T) {
	runDir := t.TempDir()
	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-002",
		Findings: []artifacts.FindingItem{
			{
				FindingID: "case-001", SliceID: "case-001",
				Status: "needs_review", Severity: "high", Confidence: "medium",
				Files: []string{"f.rs"}, Summary: "Suspicious",
			},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findings); err != nil {
		t.Fatal(err)
	}

	// Inputs:
	//   verdict="f" (false_positive)
	//   fp_reason="1" (wrong_layer)
	//   severity_override="low"
	//   confidence_override=""  (keep)
	//   tags=""
	//   notes="policy is enforced one layer up"
	input := "f\n1\nlow\n\n\npolicy is enforced one layer up\n"

	var output bytes.Buffer
	cfg := config.Config{Command: "review", RunDir: runDir}
	err := review.RunWithIO(cfg, strings.NewReader(input), &output,
		time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("review: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(runfs.ReviewDir(runDir), "review-001.json"))
	if err != nil {
		t.Fatalf("read review: %v", err)
	}
	var rec artifacts.ReviewRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.Verdict != artifacts.VerdictFalsePositive {
		t.Errorf("Verdict=%q want %q", rec.Verdict, artifacts.VerdictFalsePositive)
	}
	if rec.FPReason != artifacts.FPWrongLayer {
		t.Errorf("FPReason=%q want %q", rec.FPReason, artifacts.FPWrongLayer)
	}
	if rec.CorrectedSeverity != "low" {
		t.Errorf("CorrectedSeverity=%q want low", rec.CorrectedSeverity)
	}
	if rec.ConfidenceOverride != "" {
		t.Errorf("ConfidenceOverride=%q want empty (kept)", rec.ConfidenceOverride)
	}
	if !strings.Contains(rec.Notes, "policy is enforced") {
		t.Errorf("Notes=%q", rec.Notes)
	}
}
