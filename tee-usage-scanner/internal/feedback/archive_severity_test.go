package feedback_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// writeReviewRecords lays down a review_records.jsonl exactly the way
// `teecheck review` does, so the archive path under test reads real
// on-disk records rather than an in-memory struct.
func writeReviewRecords(t *testing.T, runDir string, records ...artifacts.ReviewRecord) {
	t.Helper()
	jsonlPath := runfs.ReviewRecordsPath(runDir)
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
}

// TestArchivePageShowsHumanCorrectedSeverity asserts on the rendered
// knowledge-base page, not on the struct field: the bug this guards
// against was that CorrectedSeverity was populated on the record and
// the page still printed an empty Severity line.
//
// The curator LLM is forced to fail so the deterministic archive
// renderer (formatArchiveContent) is the code under test.
func TestArchivePageShowsHumanCorrectedSeverity(t *testing.T) {
	tests := []struct {
		name       string
		record     artifacts.ReviewRecord
		wantLine   string
		unwantLine string
	}{
		{
			name: "new write carries only corrected_severity",
			record: artifacts.ReviewRecord{
				SchemaVersion:     "teecheck.review_record.v1",
				CaseID:            "case-001",
				FindingID:         "case-001",
				Verdict:           artifacts.VerdictTruePositive,
				CorrectedSeverity: "critical",
				ReviewedAt:        "2026-04-06T12:00:00Z",
			},
			wantLine: "**Severity**: critical",
		},
		{
			name: "legacy record carries only severity",
			record: artifacts.ReviewRecord{
				SchemaVersion: "teecheck.review_record.v1",
				CaseID:        "case-001",
				FindingID:     "case-001",
				Verdict:       artifacts.VerdictTruePositive,
				Severity:      "medium",
				ReviewedAt:    "2026-04-06T12:00:00Z",
			},
			wantLine: "**Severity**: medium",
		},
		{
			name: "both present shows the human correction",
			record: artifacts.ReviewRecord{
				SchemaVersion:     "teecheck.review_record.v1",
				CaseID:            "case-001",
				FindingID:         "case-001",
				Verdict:           artifacts.VerdictTruePositive,
				CorrectedSeverity: "low",
				Severity:          "high",
				ReviewedAt:        "2026-04-06T12:00:00Z",
			},
			wantLine:   "**Severity**: low",
			unwantLine: "**Severity**: high",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page := renderArchivePage(t, tc.record)
			if !strings.Contains(page, tc.wantLine) {
				t.Errorf("archive page missing %q, got:\n%s", tc.wantLine, page)
			}
			if tc.unwantLine != "" && strings.Contains(page, tc.unwantLine) {
				t.Errorf("archive page contains %q but should show the correction, got:\n%s", tc.unwantLine, page)
			}
		})
	}
}

// TestArchivePageShowsConfidenceOverride guards the second reviewer
// input that `teecheck review` collects and nothing used to read.
func TestArchivePageShowsConfidenceOverride(t *testing.T) {
	page := renderArchivePage(t, artifacts.ReviewRecord{
		SchemaVersion:      "teecheck.review_record.v1",
		CaseID:             "case-001",
		FindingID:          "case-001",
		Verdict:            artifacts.VerdictTruePositive,
		CorrectedSeverity:  "high",
		ConfidenceOverride: "low",
		ReviewedAt:         "2026-04-06T12:00:00Z",
	})
	if !strings.Contains(page, "**Confidence**: low") {
		t.Errorf("archive page missing reviewer confidence override, got:\n%s", page)
	}
}

// TestArchivePageOmitsBlankConfidence keeps the page free of empty
// scaffolding when the reviewer pressed enter to keep the agent value.
func TestArchivePageOmitsBlankConfidence(t *testing.T) {
	page := renderArchivePage(t, artifacts.ReviewRecord{
		SchemaVersion:     "teecheck.review_record.v1",
		CaseID:            "case-001",
		FindingID:         "case-001",
		Verdict:           artifacts.VerdictTruePositive,
		CorrectedSeverity: "high",
		ReviewedAt:        "2026-04-06T12:00:00Z",
	})
	if strings.Contains(page, "**Confidence**") {
		t.Errorf("archive page should omit an empty confidence line, got:\n%s", page)
	}
}

// TestCuratorPromptCarriesReviewerCorrections covers the primary
// path: when the curator LLM is up it writes the archive page, so the
// reviewer's corrections have to reach its prompt too — otherwise the
// deterministic fallback would be the only page that shows them.
func TestCuratorPromptCarriesReviewerCorrections(t *testing.T) {
	runDir := t.TempDir()
	knowledgeRoot := filepath.Join(t.TempDir(), "knowledge")
	if err := knowledge.EnsureLayout(knowledgeRoot); err != nil {
		t.Fatal(err)
	}
	writeReviewRecords(t, runDir, artifacts.ReviewRecord{
		SchemaVersion:      "teecheck.review_record.v1",
		CaseID:             "case-001",
		FindingID:          "case-001",
		Verdict:            artifacts.VerdictTruePositive,
		CorrectedSeverity:  "critical",
		ConfidenceOverride: "low",
		ReviewedAt:         "2026-04-06T12:00:00Z",
	})

	client := &llmtest.FakeClient{Responses: []string{`{"archive_content":"# case-001\n","wiki_updates":[],"queries":[]}`}}
	cfg := config.Config{Command: "feedback", RunDir: runDir, KnowledgeRoot: knowledgeRoot}
	var out bytes.Buffer
	if err := feedback.RunWithBus(cfg, client, &out, agentbus.New(0)); err != nil {
		t.Fatalf("feedback.RunWithBus: %v", err)
	}
	if len(client.Calls) == 0 {
		t.Fatal("curator LLM was never called")
	}
	prompt := client.Calls[0].Messages[0].Content
	for _, want := range []string{"Severity: critical", "Confidence: low"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("curator prompt missing %q, got:\n%s", want, prompt)
		}
	}
}

// renderArchivePage runs the feedback stage over a single record with
// a failing curator LLM and returns the markdown page it wrote.
func renderArchivePage(t *testing.T, record artifacts.ReviewRecord) string {
	t.Helper()
	runDir := t.TempDir()
	knowledgeRoot := filepath.Join(t.TempDir(), "knowledge")
	if err := knowledge.EnsureLayout(knowledgeRoot); err != nil {
		t.Fatal(err)
	}
	writeReviewRecords(t, runDir, record)

	findingsData := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-001",
		Findings: []artifacts.FindingItem{
			{FindingID: record.FindingID, Summary: "Missing attestation freshness", Severity: "high", Status: "confirmed_candidate"},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findingsData); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{Command: "feedback", RunDir: runDir, KnowledgeRoot: knowledgeRoot}
	client := &llmtest.FakeClient{Err: errors.New("curator offline")}
	var out bytes.Buffer
	if err := feedback.RunWithBus(cfg, client, &out, agentbus.New(0)); err != nil {
		t.Fatalf("feedback.RunWithBus: %v", err)
	}

	pagePath := filepath.Join(knowledgeRoot, "learned", "true-positive", record.FindingID+".md")
	data, err := os.ReadFile(pagePath)
	if err != nil {
		t.Fatalf("archive page not written: %v", err)
	}
	return string(data)
}
