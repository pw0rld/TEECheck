package feedback_test

import (
	"bytes"
	"encoding/json"
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

func TestFeedbackArchivesAndSuggestsWiki(t *testing.T) {
	runDir := t.TempDir()
	knowledgeRoot := filepath.Join(t.TempDir(), "knowledge")
	if err := knowledge.EnsureLayout(knowledgeRoot); err != nil {
		t.Fatal(err)
	}

	jsonlPath := runfs.ReviewRecordsPath(runDir)
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
		t.Fatal(err)
	}
	records := []artifacts.ReviewRecord{
		{
			SchemaVersion: "teecheck.review_record.v1",
			CaseID:        "case-001",
			FindingID:     "case-001",
			Verdict:       "confirmed",
			Severity:      "high",
			Tags:          []string{"attestation", "freshness"},
			Notes:         "Real issue confirmed",
			ReviewedAt:    "2026-04-06T12:00:00Z",
		},
		{
			SchemaVersion: "teecheck.review_record.v1",
			CaseID:        "case-002",
			FindingID:     "case-002",
			Verdict:       "dismissed",
			Severity:      "medium",
			Tags:          []string{"boundary"},
			Notes:         "False alarm",
			ReviewedAt:    "2026-04-06T12:01:00Z",
		},
	}
	f, err := os.Create(jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	findingsData := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         "test-001",
		Findings: []artifacts.FindingItem{
			{FindingID: "case-001", Summary: "Missing attestation freshness", Severity: "high", Status: "confirmed_candidate", Files: []string{"verify.rs"}},
			{FindingID: "case-002", Summary: "Boundary issue", Severity: "medium", Status: "needs_review", Files: []string{"bridge.rs"}},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(runDir), findingsData); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cfg := config.Config{
		Command:       "feedback",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
	}

	tpCuratorJSON := `{
		"archive_content": "# case-001\n\n**Summary**: Missing attestation freshness\n**Verdict**: confirmed\n",
		"wiki_updates": [
			{"action": "suggest_new", "page_path": "wiki/attestation.md", "content": "", "reason": "New true-positive pattern discovered"}
		],
		"queries": []
	}`
	fpCuratorJSON := `{
		"archive_content": "# case-002\n\n**Summary**: Boundary issue\n**Verdict**: dismissed\n",
		"wiki_updates": [],
		"queries": []
	}`
	client := &llmtest.FakeClient{Responses: []string{tpCuratorJSON, fpCuratorJSON}}
	bus := agentbus.New(0)

	if err := feedback.RunWithBus(cfg, client, &output, bus); err != nil {
		t.Fatalf("feedback failed: %v", err)
	}

	tpPath := filepath.Join(knowledgeRoot, "learned", "true-positive", "case-001.md")
	if _, err := os.Stat(tpPath); err != nil {
		t.Fatalf("true-positive archive not found: %v", err)
	}

	fpPath := filepath.Join(knowledgeRoot, "learned", "false-positive", "case-002.md")
	if _, err := os.Stat(fpPath); err != nil {
		t.Fatalf("false-positive archive not found: %v", err)
	}

	outStr := output.String()
	if !strings.Contains(outStr, "wiki") && !strings.Contains(outStr, "Suggest") && !strings.Contains(outStr, "Appended") {
		t.Fatalf("expected wiki-related output, got: %s", outStr)
	}
}
