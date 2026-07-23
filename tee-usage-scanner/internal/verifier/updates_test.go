package verifier

import (
	"bufio"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// ─── computeInvariantUpdates ─────────────────────────────────────────

func TestComputeInvariantUpdates_MapsStatusByVerifierVerdict(t *testing.T) {
	invs := []artifacts.ProjectInvariant{
		{InvariantID: "inv-corroborated", Status: "proposed"},
		{InvariantID: "inv-contested", Status: "proposed"},
		{InvariantID: "inv-inconclusive", Status: "proposed"},
		{InvariantID: "inv-already-satisfied", Status: "satisfied"},
	}

	for _, tc := range []struct {
		invID, memoStatus, wantNew string
	}{
		{"inv-corroborated", "corroborated", "violated_candidate"},
		{"inv-contested", "contested", "unresolved"},
		{"inv-inconclusive", "inconclusive", "unresolved"},
	} {
		updates := computeInvariantUpdates(invs, tc.memoStatus)
		found := false
		for _, u := range updates {
			if u.InvariantID == tc.invID {
				found = true
				if u.NewStatus != tc.wantNew {
					t.Errorf("%s: NewStatus=%q, want %q", tc.invID, u.NewStatus, tc.wantNew)
				}
				if u.PreviousStatus != "proposed" {
					t.Errorf("%s: PreviousStatus=%q, want proposed", tc.invID, u.PreviousStatus)
				}
			}
		}
		if !found {
			t.Errorf("no update emitted for a status change (memoStatus=%s)", tc.memoStatus)
		}
	}
}

func TestComputeInvariantUpdates_NoChangeProducesNoEntry(t *testing.T) {
	// "unresolved" verdict against an invariant already "unresolved":
	// nothing changed, no update should be emitted.
	invs := []artifacts.ProjectInvariant{{InvariantID: "inv-1", Status: "unresolved"}}
	updates := computeInvariantUpdates(invs, "inconclusive")
	if len(updates) != 0 {
		t.Errorf("expected no updates when status doesn't change, got %+v", updates)
	}
}

// ─── §3.5 append-not-overwrite ───────────────────────────────────────

// TestAppendInvariantUpdates_AppendsNotOverwrites is the direct
// mechanical proof for §7.8's "更新invariant verification status 但
// 保留原始 proposed artifact": two calls against the same run must
// both survive in the log, and the log file is opened O_APPEND so a
// second call cannot truncate the first call's entries.
func TestAppendInvariantUpdates_AppendsNotOverwrites(t *testing.T) {
	runDir := t.TempDir()

	first := []artifacts.InvariantStatusUpdate{{InvariantID: "inv-1", PreviousStatus: "proposed", NewStatus: "violated_candidate", Reason: "case-001"}}
	second := []artifacts.InvariantStatusUpdate{{InvariantID: "inv-2", PreviousStatus: "proposed", NewStatus: "unresolved", Reason: "case-002"}}

	if err := appendInvariantUpdates(runDir, "case-001", first); err != nil {
		t.Fatal(err)
	}
	if err := appendInvariantUpdates(runDir, "case-002", second); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(invariantUpdateLogPath(runDir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("log has %d lines, want 2 (both calls' entries present)", len(lines))
	}
}

// TestVerifierRun_NeverWritesProjectInvariantsFile is the strongest
// form of the append-not-overwrite guarantee: run the full Verifier
// Run() against a fixture with a real project_invariants.v1.json and
// confirm the file is byte-identical afterward, even though the run
// produces InvariantUpdates that WOULD change that invariant's
// status if applied in place.
func TestVerifierRun_NeverWritesProjectInvariantsFile(t *testing.T) {
	runDir := t.TempDir()
	repoRoot := t.TempDir()

	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "run-1", LocalPath: repoRoot}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}

	invs := []artifacts.ProjectInvariant{
		{InvariantID: "inv-1", Statement: "version must propagate", Status: "proposed", RelatedTWEs: []string{"TWE-01"}, VerificationPlan: []string{"grep for version check"}},
	}
	invPath := runfs.ProjectInvariantsPath(runDir)
	if err := runfs.WriteJSON(invPath, invs); err != nil {
		t.Fatal(err)
	}
	beforeHash := hashBytes(t, invPath)

	pack := artifacts.CasePack{
		SchemaVersion:     "teecheck.case_pack.v1",
		CaseID:            "case-001",
		Category:          "rollback",
		RelatedInvariants: []string{"inv-1"},
	}
	if err := runfs.WriteJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), pack); err != nil {
		t.Fatal(err)
	}
	hyp := artifacts.Hypothesis{SchemaVersion: "teecheck.hypothesis.v1", CaseID: "case-001", AgentID: "expert-001"}
	if err := runfs.WriteJSON(filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"), hyp); err != nil {
		t.Fatal(err)
	}
	// StaticTools "none" means buildMemo defaults to status
	// "inconclusive" (no checks ran) — computeInvariantUpdates still
	// maps that to "unresolved", a real change from the invariant's
	// starting "proposed" status, so this run DOES produce an update,
	// not a no-op.
	challenge := artifacts.Challenge{SchemaVersion: "teecheck.challenge.v1", CaseID: "case-001"}
	if err := runfs.WriteJSON(filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"), challenge); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, AgentID: "verifier-001", StaticTools: "none"}
	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if afterHash := hashBytes(t, invPath); afterHash != beforeHash {
		t.Fatalf("project_invariants.v1.json was rewritten in place — §3.5 violated")
	}

	var memo artifacts.VerificationMemo
	if err := runfs.ReadJSON(filepath.Join(runfs.VerifierDir(runDir), "verify-001.json"), &memo); err != nil {
		t.Fatal(err)
	}
	if len(memo.InvariantUpdates) != 1 || memo.InvariantUpdates[0].InvariantID != "inv-1" {
		t.Fatalf("expected memo to record an InvariantUpdate for inv-1, got %+v", memo.InvariantUpdates)
	}
	if memo.InvariantUpdates[0].PreviousStatus != "proposed" {
		t.Errorf("PreviousStatus=%q, want proposed (the untouched original)", memo.InvariantUpdates[0].PreviousStatus)
	}

	// The append-only log must ALSO carry the same update.
	logData, err := os.ReadFile(invariantUpdateLogPath(runDir))
	if err != nil {
		t.Fatalf("invariant update log not written: %v", err)
	}
	if len(logData) == 0 {
		t.Error("invariant update log is empty")
	}
}

func hashBytes(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

// TestVerifierRun_NeverRewritesToolFact is the Verifier's side of the
// §25 acceptance "Agent 不能覆盖 ToolFact JSON" — the Verifier reads
// and cites ToolFacts (via caseContext / computeEvidenceDistinctions)
// but never calls runfs.WriteJSON against a ToolFact path.
func TestVerifierRun_NeverRewritesToolFact(t *testing.T) {
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
	beforeHash := hashBytes(t, factPath)

	pack := artifacts.CasePack{SchemaVersion: "teecheck.case_pack.v1", CaseID: "case-001", Category: "rollback", ToolFactRefs: []string{factPath}}
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

	cfg := config.Config{RunDir: runDir, AgentID: "verifier-001", StaticTools: "none"}
	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if afterHash := hashBytes(t, factPath); afterHash != beforeHash {
		t.Fatalf("ToolFact %s was rewritten by the Verifier stage", factPath)
	}
}

// ─── §7.8: not_found vs proven_absent ────────────────────────────────

func TestComputeEvidenceDistinctions_ExhaustiveToolFactIsProvenAbsent(t *testing.T) {
	ctx := caseContext{
		toolFacts: []artifacts.ToolFact{
			{FactID: "fact-1", Tool: "trustir", Operation: "reverse_trace", Status: "ok", Truncated: false, CoverageGaps: nil, Locations: nil},
		},
	}
	notes := computeEvidenceDistinctions(ctx, false, nil)
	if len(notes) != 1 || notes[0].Outcome != artifacts.EvidenceProvenAbsent {
		t.Fatalf("got %+v, want one proven_absent note", notes)
	}
}

func TestComputeEvidenceDistinctions_TruncatedOrGappyIsNotFound(t *testing.T) {
	ctx := caseContext{
		toolFacts: []artifacts.ToolFact{
			{FactID: "fact-truncated", Status: "ok", Truncated: true},
			{FactID: "fact-gaps", Status: "ok", CoverageGaps: []string{"only scanned 3 of 8 call sites"}},
			{FactID: "fact-error", Status: "error"},
		},
	}
	notes := computeEvidenceDistinctions(ctx, false, nil)
	if len(notes) != 3 {
		t.Fatalf("got %d notes, want 3", len(notes))
	}
	for _, n := range notes {
		if n.Outcome != artifacts.EvidenceNotFound {
			t.Errorf("note %+v: Outcome=%q, want not_found", n, n.Outcome)
		}
	}
}

func TestComputeEvidenceDistinctions_GrepOnlySearchIsNotFound(t *testing.T) {
	notes := computeEvidenceDistinctions(caseContext{}, true, nil)
	if len(notes) != 1 || notes[0].Outcome != artifacts.EvidenceNotFound {
		t.Fatalf("got %+v, want one not_found note for grep-only search", notes)
	}
}

func TestComputeEvidenceDistinctions_ToolFactWithLocationsSkipped(t *testing.T) {
	ctx := caseContext{
		toolFacts: []artifacts.ToolFact{
			{FactID: "fact-found", Status: "ok", Locations: []artifacts.ToolLocation{{Path: "x.c", StartLine: 1}}},
		},
	}
	notes := computeEvidenceDistinctions(ctx, false, nil)
	if len(notes) != 0 {
		t.Errorf("a fact that found locations is a presence claim, not an absence one: %+v", notes)
	}
}
