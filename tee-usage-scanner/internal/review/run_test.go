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

	// Prompt order (Phase 1.5 — same shape as Phase 1):
	//   verdict, [reason_code if FP], severity_override,
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
	//   reason_code="1" (outer_validation_missed)
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
	if rec.ReasonCode != artifacts.ReasonOuterValidationMissed {
		t.Errorf("ReasonCode=%q want %q", rec.ReasonCode, artifacts.ReasonOuterValidationMissed)
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

// TestReviewFlow_NeedsContextAsksReason locks in the C2 change:
// reason_code is prompted for every non-TP verdict, not just FP. A
// reviewer who chooses needs_context now gets a reason prompt where
// Phase 1 would have skipped it.
func TestReviewFlow_NeedsContextAsksReason(t *testing.T) {
	runDir := t.TempDir()
	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-nc",
		Findings: []artifacts.FindingItem{
			{
				FindingID: "case-001", SliceID: "case-001",
				Status: "needs_review", Severity: "medium", Confidence: "low",
				Files: []string{"f.rs"}, Summary: "Maybe missing TCB check",
			},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findings); err != nil {
		t.Fatal(err)
	}

	// verdict="n" (needs_context), reason="3" (snippet_truncation),
	// severity kept, confidence kept, tags empty, notes.
	input := "n\n3\n\n\n\nneed to see caller\n"
	cfg := config.Config{Command: "review", RunDir: runDir}
	err := review.RunWithIO(cfg, strings.NewReader(input), &bytes.Buffer{},
		time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(runfs.ReviewDir(runDir), "review-001.json"))
	var rec artifacts.ReviewRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.Verdict != artifacts.VerdictNeedsContext {
		t.Errorf("Verdict=%q want %q", rec.Verdict, artifacts.VerdictNeedsContext)
	}
	if rec.ReasonCode != artifacts.ReasonSnippetTruncation {
		t.Errorf("ReasonCode=%q want %q (NC must prompt for reason in Phase 1.5)",
			rec.ReasonCode, artifacts.ReasonSnippetTruncation)
	}
}

// TestReviewFlow_DesignRiskAndNoIssueObserved exercises the two new
// Phase 1.5 verdicts. Design risk is a real reviewer judgment;
// no_issue_observed is the verdict for findings the scanner itself
// downgraded but that still surfaced to review.
func TestReviewFlow_DesignRiskAndNoIssueObserved(t *testing.T) {
	runDir := t.TempDir()
	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-dr-nio",
		Findings: []artifacts.FindingItem{
			{FindingID: "case-001", SliceID: "case-001", Status: "needs_review",
				Severity: "high", Confidence: "medium", Files: []string{"a.rs"},
				Summary: "Cross-cutting design observation"},
			{FindingID: "case-002", SliceID: "case-002", Status: "no_issue_observed",
				Severity: "low", Confidence: "low", Files: []string{"b.rs"},
				Summary: "Already self-rejected"},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findings); err != nil {
		t.Fatal(err)
	}

	// First finding: design_risk + reason 7 (other) + notes.
	// Second finding: no_issue_observed + skip reason (enter) + notes.
	// Each finding consumes 6 lines after the verdict prompt:
	//   verdict, reason, severity, confidence, tags, notes
	input := "d\n7\n\n\n\nlayered concern\n" +
		"o\n\n\n\n\nscanner already dismissed\n"
	cfg := config.Config{Command: "review", RunDir: runDir}
	err := review.RunWithIO(cfg, strings.NewReader(input), &bytes.Buffer{},
		time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("review: %v", err)
	}

	// First record: design_risk + ReasonOther
	data1, _ := os.ReadFile(filepath.Join(runfs.ReviewDir(runDir), "review-001.json"))
	var r1 artifacts.ReviewRecord
	if err := json.Unmarshal(data1, &r1); err != nil {
		t.Fatalf("parse 1: %v", err)
	}
	if r1.Verdict != artifacts.VerdictDesignRisk {
		t.Errorf("rec 1 Verdict=%q want %q", r1.Verdict, artifacts.VerdictDesignRisk)
	}
	if r1.ReasonCode != artifacts.ReasonOther {
		t.Errorf("rec 1 ReasonCode=%q want %q", r1.ReasonCode, artifacts.ReasonOther)
	}

	// Second record: no_issue_observed + empty reason (reviewer
	// pressed enter — the prompt allowed it)
	data2, _ := os.ReadFile(filepath.Join(runfs.ReviewDir(runDir), "review-002.json"))
	var r2 artifacts.ReviewRecord
	if err := json.Unmarshal(data2, &r2); err != nil {
		t.Fatalf("parse 2: %v", err)
	}
	if r2.Verdict != artifacts.VerdictNoIssueObserved {
		t.Errorf("rec 2 Verdict=%q want %q", r2.Verdict, artifacts.VerdictNoIssueObserved)
	}
	if r2.ReasonCode != "" {
		t.Errorf("rec 2 ReasonCode=%q want empty (reviewer skipped)", r2.ReasonCode)
	}
}
