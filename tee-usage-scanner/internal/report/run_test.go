package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestRun_DeterministicallyIncludesEveryFindingAndFullPacket(t *testing.T) {
	dir := reportFixture(t)
	client := &llmtest.FakeClient{Default: "Narrative mentions only finding-low."}

	if err := Run(config.Config{RunDir: dir}, client); err != nil {
		t.Fatalf("Run: %v", err)
	}
	report := readReport(t, dir)
	for _, want := range []string{
		"finding-high", "finding-low", "evidence-high", "evidence-low",
		"core/high.c:42", "human-question-high", "PACKET_TAIL_MUST_SURVIVE",
		"Candidates", "120001", "aggregate_token_budget",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report omitted %q", want)
		}
	}
	if strings.Index(report, "| `finding-high`") > strings.Index(report, "| `finding-low`") {
		t.Fatal("high-severity finding was not ordered before low-severity finding")
	}
	if len(client.Calls) != 1 {
		t.Fatalf("LLM calls = %d, want one bounded narrative call", len(client.Calls))
	}
	if strings.Contains(client.Calls[0].Messages[0].Content, "PACKET_TAIL_MUST_SURVIVE") {
		t.Fatal("full packets should not be sent to the narrative model")
	}
}

func TestRun_WritesFactualReportWhenNarrativeModelFails(t *testing.T) {
	dir := reportFixture(t)
	client := &llmtest.FakeClient{Err: errors.New("provider unavailable")}

	if err := Run(config.Config{RunDir: dir}, client); err != nil {
		t.Fatalf("Run must not lose the factual report when narrative generation fails: %v", err)
	}
	report := readReport(t, dir)
	if !strings.Contains(report, "Narrative unavailable") || !strings.Contains(report, "finding-high") {
		t.Fatalf("fallback report is incomplete:\n%s", report)
	}
}

func reportFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "report-run",
		RepoURL: "https://example.test/repo", Commit: "abc123", Focus: "tee",
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(dir), manifest); err != nil {
		t.Fatal(err)
	}
	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2", RunID: "report-run",
		Findings: []artifacts.FindingItem{
			{
				FindingID: "finding-low", SliceID: "slice-low", Status: "needs_review",
				Severity: "low", Confidence: "low", Summary: "low summary",
				Files: []string{"core/low.c"}, Evidence: []string{"evidence-low"},
			},
			{
				FindingID: "finding-high", SliceID: "slice-high", Status: "likely_issue",
				Severity: "high", Confidence: "high", Summary: "high summary",
				Files:     []string{"core/high.c"},
				Locations: []artifacts.FindingLocation{{Path: "core/high.c", StartLine: 42}},
				Evidence:  []string{"evidence-high"},
				Sections: &artifacts.ArbiterSections{
					AnchoredToolFacts:    []string{"anchored-high"},
					HumanReviewQuestions: []string{"human-question-high"},
				},
			},
		},
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(dir), findings); err != nil {
		t.Fatal(err)
	}
	bundle := artifacts.EvidenceBundle{PlannerMeta: artifacts.PlannerMeta{
		RoundsUsed: 10, RoundsBudget: 18, TokensUsed: 120001,
		TerminationReason: "aggregate_token_budget",
	}}
	if err := runfs.WriteJSON(runfs.EvidenceBundlePath(dir), bundle); err != nil {
		t.Fatal(err)
	}
	packet := strings.Repeat("packet body\n", 900) + "PACKET_TAIL_MUST_SURVIVE\n"
	packetPath := filepath.Join(runfs.ArbiterPacketsDir(dir), "review-001.md")
	if err := os.MkdirAll(filepath.Dir(packetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packetPath, []byte(packet), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readReport(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "08_report", "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
