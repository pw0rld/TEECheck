package arbiter

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// ─── buildSections: aggregation, not new judgment ───────────────────

func TestBuildSections_PopulatesAllEightSections(t *testing.T) {
	pack := artifacts.CasePack{
		CaseID:           "case-001",
		CoverageGaps:     []string{"only 2 of 5 call sites reviewed"},
		MissingLinks:     []string{"loader role"},
		RequiredEvidence: []string{"reverse trace to authority"},
		OpenQuestions:    []string{"is this the real trust boundary?"},
	}
	hyp := artifacts.Hypothesis{Title: "t", Summary: "s", SuspectedIssue: "si", Classification: "standard"}
	challenge := artifacts.Challenge{KeyDifferences: []string{"independent view disagrees"}, RemainingQuestions: []string{"q1"}}
	memo := artifacts.VerificationMemo{
		Status:               "contested",
		EvidenceDistinctions: []artifacts.EvidenceDistinctionNote{{Claim: "c", Outcome: artifacts.EvidenceNotFound, Note: "n"}},
		InvariantUpdates:     []artifacts.InvariantStatusUpdate{{InvariantID: "inv-1", PreviousStatus: "proposed", NewStatus: "unresolved", Reason: "r"}},
	}
	caseCtx := caseContext{
		archModel:        &artifacts.ArchitectureModel{Parties: []artifacts.ArchitectureElement{{ID: "p1", Name: "Host", State: artifacts.EvidenceInferred}}},
		invariants:       []artifacts.ProjectInvariant{{InvariantID: "inv-1", Statement: "version propagates", Status: "proposed"}},
		toolFacts:        []artifacts.ToolFact{{FactID: "fact-1", Tool: "trustir", Operation: "reverse_trace", Status: "ok"}},
		missingToolFacts: []string{"/missing/fact.json"},
	}
	independent := artifacts.ChallengerIndependentView{IssuePresent: true, Reasoning: "saw a marker"}

	sections := buildSections(pack, hyp, challenge, memo, caseCtx, independent)

	if len(sections.AnchoredToolFacts) != 2 {
		t.Errorf("AnchoredToolFacts = %v, want 2 entries (1 fact + 1 missing)", sections.AnchoredToolFacts)
	}
	if len(sections.ArchitectureEvidenceStatus) != 1 || !strings.Contains(sections.ArchitectureEvidenceStatus[0], "inferred") {
		t.Errorf("ArchitectureEvidenceStatus = %v", sections.ArchitectureEvidenceStatus)
	}
	if len(sections.InvariantVerificationStatus) != 1 || !strings.Contains(sections.InvariantVerificationStatus[0], "Verifier proposes") {
		t.Errorf("InvariantVerificationStatus = %v", sections.InvariantVerificationStatus)
	}
	if !strings.Contains(sections.ExpertHypothesis, "standard") {
		t.Errorf("ExpertHypothesis missing classification: %q", sections.ExpertHypothesis)
	}
	if !strings.Contains(sections.IndependentChallengerResult, "saw a marker") || !strings.Contains(sections.IndependentChallengerResult, "independent view disagrees") {
		t.Errorf("IndependentChallengerResult missing content: %q", sections.IndependentChallengerResult)
	}
	if !strings.Contains(sections.VerifierResolution, "contested") || !strings.Contains(sections.VerifierResolution, "not-found") {
		t.Errorf("VerifierResolution missing content: %q", sections.VerifierResolution)
	}
	if len(sections.RemainingCoverageGaps) != 3 { // CoverageGaps + MissingLinks + RequiredEvidence
		t.Errorf("RemainingCoverageGaps = %v, want 3 entries", sections.RemainingCoverageGaps)
	}
	if len(sections.HumanReviewQuestions) < 4 { // 3 static + case-specific
		t.Errorf("HumanReviewQuestions = %v, want at least 4", sections.HumanReviewQuestions)
	}
}

// ─── §25 acceptance: Arbiter never rewrites a ToolFact ──────────────

func hashArbiterFile(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func TestArbiterRun_NeverRewritesToolFactOrInvariants(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()

	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "run-1", LocalPath: repoRoot}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}

	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "fact-001", Tool: "trustir", Operation: "reverse_trace", Status: "ok"}
	factPath := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if err := runfs.WriteJSON(factPath, fact); err != nil {
		t.Fatal(err)
	}
	beforeFactHash := hashArbiterFile(t, factPath)

	invs := artifacts.ProjectInvariants{
		SchemaVersion: "teecheck.project_invariants.v1",
		RunID:         "run-1",
		Invariants:    []artifacts.ProjectInvariant{{InvariantID: "inv-1", Statement: "s", Status: "proposed"}},
	}
	invPath := runfs.ProjectInvariantsPath(runDir)
	if err := runfs.WriteJSON(invPath, invs); err != nil {
		t.Fatal(err)
	}
	beforeInvHash := hashArbiterFile(t, invPath)

	pack := artifacts.CasePack{
		SchemaVersion:     "teecheck.case_pack.v1",
		CaseID:            "case-001",
		Category:          "rollback",
		ToolFactRefs:      []string{factPath},
		RelatedInvariants: []string{"inv-1"},
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}
	hyp := artifacts.Hypothesis{SchemaVersion: "teecheck.hypothesis.v1", CaseID: "case-001", AgentID: "expert-001"}
	if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), hyp); err != nil {
		t.Fatal(err)
	}
	challenge := artifacts.Challenge{SchemaVersion: "teecheck.challenge.v1", CaseID: "case-001"}
	if err := runfs.WriteJSON(filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"), challenge); err != nil {
		t.Fatal(err)
	}
	memo := artifacts.VerificationMemo{SchemaVersion: "teecheck.verification_memo.v1", CaseID: "case-001", Status: "inconclusive"}
	if err := runfs.WriteJSON(filepath.Join(runfs.VerifierDir(runDir), "verify-001.json"), memo); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, AgentID: "arbiter-001"}
	client := &llmtest.FakeClient{Responses: []string{`{
		"status": "needs_review",
		"severity": "medium",
		"confidence": "low",
		"summary": "aggregated",
		"evidence": [],
		"review_packet_markdown": "# Packet",
		"queries": []
	}`}}
	bus := agentbus.New(0)
	if err := RunWithBus(cfg, client, bus); err != nil {
		t.Fatalf("RunWithBus: %v", err)
	}

	if afterFactHash := hashArbiterFile(t, factPath); afterFactHash != beforeFactHash {
		t.Fatalf("ToolFact %s was rewritten by the Arbiter stage", factPath)
	}
	if afterInvHash := hashArbiterFile(t, invPath); afterInvHash != beforeInvHash {
		t.Fatalf("project_invariants.v1.json was rewritten by the Arbiter stage")
	}

	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err != nil {
		t.Fatalf("findings not written: %v", err)
	}
	if len(findings.Findings) != 1 || findings.Findings[0].Sections == nil {
		t.Fatalf("expected one finding with Sections populated, got %+v", findings.Findings)
	}
	if len(findings.Findings[0].Sections.AnchoredToolFacts) != 1 {
		t.Errorf("finding.Sections.AnchoredToolFacts = %v, want the referenced fact", findings.Findings[0].Sections.AnchoredToolFacts)
	}
}
