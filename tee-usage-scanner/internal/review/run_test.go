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

	// Simulate: confirm, keep severity (empty line), tag "attestation", note
	input := "c\n\nattestation\nLooks real\n"
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
	if rec.Verdict != "confirmed" {
		t.Fatalf("expected verdict confirmed, got %s", rec.Verdict)
	}
	if rec.Severity != "high" {
		t.Fatalf("expected severity high, got %s", rec.Severity)
	}
	if len(rec.Tags) != 1 || rec.Tags[0] != "attestation" {
		t.Fatalf("unexpected tags: %v", rec.Tags)
	}

	jsonlPath := runfs.ReviewRecordsPath(runDir)
	if _, err := os.Stat(jsonlPath); err != nil {
		t.Fatalf("review_records.jsonl not found: %v", err)
	}
}
