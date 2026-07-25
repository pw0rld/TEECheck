package expert

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// ─── sliceArchitecture / sliceInvariants ────────────────────────────

func TestSliceArchitecture_KeepsOnlyReferencedIDs(t *testing.T) {
	model := artifacts.ArchitectureModel{
		SchemaVersion: "teecheck.architecture.v1",
		Parties: []artifacts.ArchitectureElement{
			{ID: "party-1", Name: "Host"},
			{ID: "party-2", Name: "TA"},
		},
		Boundaries: []artifacts.ArchitectureRelation{
			{ID: "boundary-1", From: "party-1", To: "party-2"},
		},
	}
	sliced := sliceArchitecture(model, []string{"party-2"})
	if len(sliced.Parties) != 1 || sliced.Parties[0].ID != "party-2" {
		t.Fatalf("Parties = %+v, want only party-2", sliced.Parties)
	}
	if len(sliced.Boundaries) != 0 {
		t.Fatalf("Boundaries = %+v, want none (boundary-1 not referenced)", sliced.Boundaries)
	}
}

func TestSliceArchitecture_EmptyRefsProducesEmptyModel(t *testing.T) {
	model := artifacts.ArchitectureModel{
		Parties: []artifacts.ArchitectureElement{{ID: "party-1"}},
	}
	sliced := sliceArchitecture(model, nil)
	if len(sliced.Parties) != 0 {
		t.Errorf("expected no parties for empty refs, got %+v", sliced.Parties)
	}
}

func TestSliceInvariants_FiltersAndPreservesOrder(t *testing.T) {
	all := []artifacts.ProjectInvariant{
		{InvariantID: "inv-a", Statement: "a"},
		{InvariantID: "inv-b", Statement: "b"},
		{InvariantID: "inv-c", Statement: "c"},
	}
	got := sliceInvariants(all, []string{"inv-c", "inv-a"})
	if len(got) != 2 || got[0].InvariantID != "inv-c" || got[1].InvariantID != "inv-a" {
		t.Fatalf("got %+v, want [inv-c, inv-a] in that order", got)
	}
}

// ─── loadCaseContext: read-only against ToolFacts ───────────────────

func TestLoadCaseContext_ReadsAllFourEvidenceSources(t *testing.T) {
	runDir := t.TempDir()

	if err := os.MkdirAll(filepath.Dir(runfs.TWEAgentContextPath(runDir)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runfs.TWEAgentContextPath(runDir), []byte("TWE-CONTEXT-MARKER"), 0o644); err != nil {
		t.Fatal(err)
	}

	model := artifacts.ArchitectureModel{
		Parties: []artifacts.ArchitectureElement{{ID: "party-1", Name: "Host", State: artifacts.EvidenceObserved}},
	}
	if err := runfs.WriteJSON(runfs.ArchitectureModelPath(runDir), model); err != nil {
		t.Fatal(err)
	}

	invs := artifacts.ProjectInvariants{
		SchemaVersion: "teecheck.project_invariants.v1",
		RunID:         "run-1",
		Invariants: []artifacts.ProjectInvariant{
			{InvariantID: "inv-1", Statement: "version must propagate", Status: "proposed"},
		},
	}
	if err := runfs.WriteJSON(runfs.ProjectInvariantsPath(runDir), invs); err != nil {
		t.Fatal(err)
	}

	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "fact-001",
		Tool:          "trustir",
		Operation:     "reverse_trace",
		Status:        "ok",
	}
	factPath := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if err := runfs.WriteJSON(factPath, fact); err != nil {
		t.Fatal(err)
	}

	pack := artifacts.CasePack{
		CaseID:            "case-001",
		ArchitectureRefs:  []string{"party-1"},
		RelatedInvariants: []string{"inv-1"},
		ToolFactRefs:      []string{factPath, "/nonexistent/missing.json"},
	}

	ctx := loadCaseContext(runDir, pack)
	if ctx.tweText != "TWE-CONTEXT-MARKER" {
		t.Errorf("tweText = %q", ctx.tweText)
	}
	if ctx.archModel == nil || len(ctx.archModel.Parties) != 1 {
		t.Fatalf("archModel not sliced correctly: %+v", ctx.archModel)
	}
	if len(ctx.invariants) != 1 || ctx.invariants[0].InvariantID != "inv-1" {
		t.Fatalf("invariants not sliced correctly: %+v", ctx.invariants)
	}
	if len(ctx.toolFacts) != 1 || ctx.toolFacts[0].FactID != "fact-001" {
		t.Fatalf("toolFacts not loaded correctly: %+v", ctx.toolFacts)
	}
	if len(ctx.missingToolFacts) != 1 || ctx.missingToolFacts[0] != "/nonexistent/missing.json" {
		t.Fatalf("missingToolFacts = %+v, want the unresolved ref recorded", ctx.missingToolFacts)
	}
}

// hashFile returns the sha256 of a file's bytes, used to prove a
// stage never rewrote it.
func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return string(sum[:])
}

// TestRunWithEvents_NeverRewritesToolFact is the §25 acceptance
// mechanical proof for Expert's side of "Agent 不能覆盖 ToolFact JSON":
// a ToolFact is byte-identical before and after RunWithEvents, even
// though the Expert reads and cites it.
func TestRunWithEvents_NeverRewritesToolFact(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()

	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "run-1",
		LocalPath:     repoRoot,
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}

	fact := artifacts.ToolFact{
		SchemaVersion: artifacts.SchemaVersionToolFactV1,
		FactID:        "fact-001",
		Tool:          "trustir",
		Operation:     "reverse_trace",
		Status:        "ok",
		Locations:     []artifacts.ToolLocation{{Path: "src/x.c", StartLine: 10}},
	}
	factPath := runfs.TrustIRToolFactPath(runDir, fact.FactID)
	if err := runfs.WriteJSON(factPath, fact); err != nil {
		t.Fatal(err)
	}
	beforeHash := hashFile(t, factPath)

	pack := artifacts.CasePack{
		SchemaVersion: "teecheck.case_pack.v1",
		CaseID:        "case-001",
		Category:      "rollback",
		ToolFactRefs:  []string{factPath},
	}
	casePath := filepath.Join(runfs.CasePacksDir(runDir), "case-001.json")
	if err := runfs.WriteJSON(casePath, pack); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, AgentID: "expert-001"}
	fake := &llmtest.FakeClient{Responses: []string{
		`{"title":"x","summary":"x","suspected_issue":"x","confidence":"low","needs_verification":false}`,
	}}
	if err := RunWithEvents(cfg, fake, nil, nil); err != nil {
		t.Fatalf("RunWithEvents: %v", err)
	}

	afterHash := hashFile(t, factPath)
	if beforeHash != afterHash {
		t.Fatalf("ToolFact %s was rewritten by the Expert stage", factPath)
	}

	// Sanity: the hypothesis was actually written (Run did something,
	// not a no-op that trivially "didn't touch" the file).
	var h artifacts.Hypothesis
	if err := runfs.ReadJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), &h); err != nil {
		t.Fatalf("hypothesis not written: %v", err)
	}
	if h.CaseID != "case-001" {
		t.Errorf("hypothesis.CaseID = %q", h.CaseID)
	}
}

// TestBuildHypothesisLLM_PromptCarriesNewEvidenceSections proves the
// Expert's LLM prompt actually contains the TWE knowledge,
// architecture slice, invariants, and tool-fact text loaded via
// loadCaseContext — not just the Case Pack fields it already had.
func TestBuildHypothesisLLM_PromptCarriesNewEvidenceSections(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "x.c")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("int f() { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := map[string]any{
		"title": "x", "summary": "x", "suspected_issue": "x",
		"confidence": "low", "needs_verification": false,
	}
	respBytes, _ := json.Marshal(resp)
	stub := &stubLLM{responseJSON: string(respBytes)}

	caseCtx := caseContext{
		tweText: "TWE-MARKER-ROLLBACK",
		archModel: &artifacts.ArchitectureModel{
			Parties: []artifacts.ArchitectureElement{{ID: "party-1", Name: "ARCH-MARKER-HOST", State: artifacts.EvidenceObserved}},
		},
		invariants: []artifacts.ProjectInvariant{
			{InvariantID: "inv-1", Statement: "INVARIANT-MARKER-VERSION-PROPAGATION", Status: "proposed"},
		},
		toolFacts: []artifacts.ToolFact{
			{FactID: "fact-001", Tool: "trustir", Operation: "reverse_trace", Status: "ok"},
		},
	}
	pack := artifacts.CasePack{CaseID: "case-001"}
	_, err := buildHypothesisLLM(context.Background(), stub, stubToolAdapter{}, repo, pack, caseCtx, "expert-001", 0)
	if err != nil {
		t.Fatalf("buildHypothesisLLM: %v", err)
	}

	prompt := stub.gotRequest.Messages[0].Content
	for _, marker := range []string{"TWE-MARKER-ROLLBACK", "ARCH-MARKER-HOST", "INVARIANT-MARKER-VERSION-PROPAGATION", "fact-001"} {
		if !strings.Contains(prompt, marker) {
			t.Errorf("prompt missing %q\n--- prompt ---\n%s", marker, prompt)
		}
	}
}
