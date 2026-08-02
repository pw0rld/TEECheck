package planner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// ─── Test harness ────────────────────────────────────────────────────

// mockLLM is a test double for llm.Client. It returns scripted
// responses in order and captures every request for assertion.
// If Generate is called more times than there are scripts, the
// last script is repeated.
type mockLLM struct {
	scripts []string
	sent    []llm.GenerateRequest
	calls   int
}

func (m *mockLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	m.sent = append(m.sent, req)
	idx := m.calls
	m.calls++
	if idx >= len(m.scripts) {
		idx = len(m.scripts) - 1
	}
	return llm.GenerateResponse{Text: m.scripts[idx]}, nil
}

func setupFixtureRepo(t *testing.T) (repoRoot, runDir string) {
	t.Helper()
	repoRoot = t.TempDir()
	runDir = t.TempDir()

	attestRs := `use core::result::Result;

pub fn verify_quote(quote: &[u8]) -> Result<(), Error> {
    // no freshness check
    if quote.is_empty() {
        return Err(Error::Empty);
    }
    Ok(())
}

pub enum Error {
    Empty,
}
`
	writeRepoFile(t, repoRoot, "src/attest.rs", attestRs)
	writeRunManifest(t, repoRoot, runDir)

	return repoRoot, runDir
}

// writeRunManifest puts a valid 00_manifest.json in the run dir. Without it
// runfs.LoadManifest fails inside planner.Run and the candidate-derived
// ("thin") Case Pack branch is skipped entirely — which is exactly what
// happened in every planner test until this was added, leaving that half of
// Run's output untested.
func writeRunManifest(t *testing.T, repoRoot, runDir string) {
	t.Helper()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "test-run",
		LocalPath:     repoRoot,
		Commit:        "abcdef1234567",
		Focus:         "tee",
	}); err != nil {
		t.Fatal(err)
	}
}

func writeRepoFile(t *testing.T, repoRoot, rel, content string) {
	t.Helper()
	full := filepath.Join(repoRoot, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func defaultTestBudget() planner.Budget {
	return planner.Budget{
		MaxRounds:        8,
		MaxTokens:        120000,
		PerActionTimeout: 30 * time.Second,
		WallClock:        10 * time.Minute,
	}
}

// ─── Happy path ──────────────────────────────────────────────────────

func TestPlannerRun_HappyPath4Rounds(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"see what's in the repo","actions":[{"name":"list_dir","args":{"path":"."}}]}`,
		`{"thought":"ripgrep for verify","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"read it","actions":[{"name":"read_file","args":{"path":"src/attest.rs","start":1,"end":20}}]}`,
		`{"thought":"found a candidate","actions":[{"name":"done","args":{"summary":"verify_quote lacks freshness","candidates":[{"id":"c1","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["No nonce check"],"confidence":0.8}]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:       "test-happy",
		RepoRoot:    repoRoot,
		RunDir:      runDir,
		Profile:     planner.PromptProfile{Focus: "tee"},
		Client:      client,
		Registry:    reg,
		Budget:      defaultTestBudget(),
		Temperature: 0,
	})

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Bundle == nil {
		t.Fatal("Bundle is nil")
	}
	if result.Bundle.PlannerMeta.TerminationReason != "llm_done" {
		t.Errorf("TerminationReason = %q, want llm_done", result.Bundle.PlannerMeta.TerminationReason)
	}
	if result.Bundle.PlannerMeta.RoundsUsed != 4 {
		t.Errorf("RoundsUsed = %d, want 4", result.Bundle.PlannerMeta.RoundsUsed)
	}
	if len(result.Bundle.Candidates) != 1 {
		t.Fatalf("Candidates len = %d, want 1", len(result.Bundle.Candidates))
	}
	c := result.Bundle.Candidates[0]
	if c.ID != "c1" {
		t.Errorf("Candidate.ID = %q, want c1", c.ID)
	}
	if len(c.Paths) != 1 || c.Paths[0] != "src/attest.rs" {
		t.Errorf("Candidate.Paths = %v, want [src/attest.rs]", c.Paths)
	}
	if result.Bundle.FinalSummary != "verify_quote lacks freshness" {
		t.Errorf("FinalSummary = %q", result.Bundle.FinalSummary)
	}

	roundsData, err := os.ReadFile(filepath.Join(runDir, "04_planner", "rounds.jsonl"))
	if err != nil {
		t.Fatalf("read rounds.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(roundsData), "\n"), "\n")
	if len(lines) != 4 {
		t.Errorf("rounds.jsonl line count = %d, want 4", len(lines))
	}

	// Round 1's list_dir action must have actually listed the fixture
	// repo (proves the substituted action round is real, not a no-op).
	var round1 artifacts.RoundRecord
	if err := json.Unmarshal([]byte(lines[0]), &round1); err != nil {
		t.Fatal(err)
	}
	if len(round1.Observations) != 1 {
		t.Fatalf("round 1 observations = %d, want 1", len(round1.Observations))
	}
	obs := round1.Observations[0]
	if !obs.OK {
		t.Errorf("round 1 list_dir observation should be OK, got error: %q", obs.Error)
	}
	if !strings.Contains(obs.Output, "src") {
		t.Errorf("round 1 list_dir output should mention src/, got: %q", obs.Output)
	}

	if _, err := os.Stat(filepath.Join(runDir, "04_planner", "evidence_bundle.json")); err != nil {
		t.Errorf("evidence_bundle.json missing: %v", err)
	}
}

// ─── Budget exhaustion ───────────────────────────────────────────────

func TestPlannerRun_BudgetExhaustedByRounds(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"list_dir","args":{"path":"."}}]}`,
		`{"thought":"r2","actions":[{"name":"list_dir","args":{"path":".","depth":1}}]}`,
		`{"thought":"r3","actions":[{"name":"list_dir","args":{"path":"src"}}]}`,
		`{"thought":"r4","actions":[{"name":"ripgrep","args":{"pattern":"verify","globs":["*.rs"]}}]}`,
		`{"thought":"r5","actions":[{"name":"ripgrep","args":{"pattern":"quote","globs":["*.rs"]}}]}`,
		`{"thought":"r6","actions":[{"name":"ripgrep","args":{"pattern":"attest","globs":["*.rs"]}}]}`,
		`{"thought":"r7","actions":[{"name":"ripgrep","args":{"pattern":"key","globs":["*.rs"]}}]}`,
		`{"thought":"r8","actions":[{"name":"ripgrep","args":{"pattern":"seal","globs":["*.rs"]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-exhaust",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
	})

	if result.Bundle.PlannerMeta.RoundsUsed != 8 {
		t.Errorf("RoundsUsed = %d, want 8", result.Bundle.PlannerMeta.RoundsUsed)
	}
	if result.Bundle.PlannerMeta.TerminationReason != "max_rounds" {
		t.Errorf("TerminationReason = %q, want max_rounds", result.Bundle.PlannerMeta.TerminationReason)
	}
	if len(result.Bundle.Candidates) != 0 {
		t.Errorf("no done was called, candidates should be 0, got %d", len(result.Bundle.Candidates))
	}
}

// ─── Loop detection ──────────────────────────────────────────────────

func TestPlannerRun_LoopDetectorRejectsThirdIdenticalCall(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	dup := `{"thought":"same again","actions":[{"name":"ripgrep","args":{"pattern":"verify","globs":["*.rs"]}}]}`
	client := &mockLLM{scripts: []string{
		dup,
		dup,
		dup,
		`{"thought":"stopping","actions":[{"name":"done","args":{"summary":"done","candidates":[]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-loop",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
	})

	if result.Err != nil {
		t.Fatalf("unexpected: %v", result.Err)
	}

	roundsData, err := os.ReadFile(filepath.Join(runDir, "04_planner", "rounds.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(roundsData), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 rounds, got %d", len(lines))
	}

	var round3 artifacts.RoundRecord
	if err := json.Unmarshal([]byte(lines[2]), &round3); err != nil {
		t.Fatal(err)
	}
	if len(round3.Observations) == 0 {
		t.Fatal("round 3 has no observations")
	}
	obs := round3.Observations[0]
	if obs.OK {
		t.Errorf("round 3 observation should be a rejection, got OK=true")
	}
	if !strings.Contains(obs.Error, "loop detector") {
		t.Errorf("round 3 error should mention loop detector, got: %q", obs.Error)
	}
}

// ─── Malformed LLM response ──────────────────────────────────────────

func TestPlannerRun_MalformedResponseTerminates(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`this is not JSON at all`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-malformed",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
	})

	if result.Bundle.PlannerMeta.TerminationReason != "llm_malformed" {
		t.Errorf("TerminationReason = %q, want llm_malformed", result.Bundle.PlannerMeta.TerminationReason)
	}
	roundsData, err := os.ReadFile(filepath.Join(runDir, "04_planner", "rounds.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(roundsData), "unparseable") {
		t.Errorf("rounds.jsonl should record the unparseable response, got: %s", string(roundsData))
	}
}

// ─── Path hallucination dropped ──────────────────────────────────────

func TestPlannerRun_HallucinatedPathsDroppedAndRecorded(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"mixed","candidates":[` +
			`{"id":"real","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["real"]},` +
			`{"id":"fake","kind":"attestation","priority":"high","paths":["sgx/svc/src/key.rs"],"symbols":["ghost"],"why_selected":["hallucinated"]}` +
			`]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-hallucination",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
	})

	if result.Err != nil {
		t.Fatalf("unexpected: %v", result.Err)
	}
	if len(result.Bundle.Candidates) != 1 {
		t.Fatalf("want 1 surviving candidate, got %d", len(result.Bundle.Candidates))
	}
	if result.Bundle.Candidates[0].ID != "real" {
		t.Errorf("surviving candidate ID = %q, want real", result.Bundle.Candidates[0].ID)
	}
	if len(result.Bundle.Errors) == 0 {
		t.Errorf("expected hallucinated path errors, got none")
	}
	foundHallucinationErr := false
	for _, e := range result.Bundle.Errors {
		if strings.Contains(e.Error, "hallucinated") || strings.Contains(e.Error, "not found") {
			foundHallucinationErr = true
		}
	}
	if !foundHallucinationErr {
		t.Errorf("no 'hallucinated' error in Bundle.Errors: %+v", result.Bundle.Errors)
	}

	// The candidate half of the done payload must reach RunResult.CasePacks
	// as a thin pack — and only the surviving candidate may. This is the
	// assertion that fails if Run ever returns `packs` (rich only) instead
	// of `merged`, or if the hallucinated candidate leaks past
	// convertCandidates into a pack.
	if len(result.CasePacks) != 1 {
		t.Fatalf("CasePacks = %d, want exactly 1 thin pack for the surviving candidate: %+v", len(result.CasePacks), result.CasePacks)
	}
	got := result.CasePacks[0]
	if len(got.TargetFiles) != 1 || got.TargetFiles[0] != "src/attest.rs" {
		t.Fatalf("CasePacks[0].TargetFiles = %v, want [src/attest.rs] — the real path, not the hallucinated one", got.TargetFiles)
	}
	for _, f := range got.TargetFiles {
		if strings.Contains(f, "sgx/svc") {
			t.Fatalf("hallucinated path reached a Case Pack: %v", got.TargetFiles)
		}
	}
}

// ─── Observed paths in prompt ────────────────────────────────────────

func TestPlannerRun_FinalRoundPromptIncludesObservedPaths(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"read_file","args":{"path":"src/attest.rs","start":1,"end":20}}]}`,
		`{"thought":"final","actions":[{"name":"done","args":{"summary":"ok","candidates":[]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	budget := defaultTestBudget()
	budget.MaxRounds = 2

	_ = planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-observed-paths-prompt",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   budget,
	})

	if len(client.sent) < 2 {
		t.Fatalf("expected 2 LLM calls, got %d", len(client.sent))
	}
	round2Msg := client.sent[1].Messages[0].Content
	if !strings.Contains(round2Msg, "FINAL ROUND") {
		t.Errorf("final round prompt missing FINAL ROUND block")
	}
	if !strings.Contains(round2Msg, "OBSERVED PATHS") {
		t.Errorf("final round prompt missing OBSERVED PATHS block")
	}
	if !strings.Contains(round2Msg, "src/attest.rs") {
		t.Errorf("final round prompt missing the observed path src/attest.rs")
	}
}

// ─── Sticky TWE playbook detail (Fix 1) ───────────────────────────────

// fakePlaybookSource is a minimal actions.PlaybookDetailSource test double.
type fakePlaybookSource struct {
	byID map[string]string
}

func (f *fakePlaybookSource) Detail(tweID string) (string, bool) {
	text, ok := f.byID[tweID]
	return text, ok
}

// TestPlannerRun_PulledPlaybookDetailStaysInPromptAcrossRounds proves the
// fix for the "throttled and then evaporates" bug: once the planner pulls a
// TWE's detail via twe_playbook_detail, that full text must keep appearing
// in every subsequent round's prompt — not just the 2-round, 1500-char
// window that RECENT ROUNDS uses for ordinary action output.
func TestPlannerRun_PulledPlaybookDetailStaysInPromptAcrossRounds(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	detailText := "[TWE-STATE-001] Trusted State Rollback\nInvestigate: " + strings.Repeat("x", 2000) + "END-OF-DETAIL-MARKER\n"
	src := &fakePlaybookSource{byID: map[string]string{"TWE-STATE-001": detailText}}
	reg := actions.NewDefaultRegistryWithFacts(nil, "", src)

	client := &mockLLM{scripts: []string{
		`{"thought":"pull detail","actions":[{"name":"twe_playbook_detail","args":{"twe_id":"TWE-STATE-001"}}]}`,
		`{"thought":"r2","actions":[{"name":"list_dir","args":{"path":"."}}]}`,
		`{"thought":"r3","actions":[{"name":"list_dir","args":{"path":".","depth":1}}]}`,
		`{"thought":"r4","actions":[{"name":"ripgrep","args":{"pattern":"verify","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"ok","candidates":[]}}]}`,
	}}

	budget := defaultTestBudget()
	budget.MaxRounds = 5

	_ = planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-sticky-detail",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   budget,
	})

	if len(client.sent) < 5 {
		t.Fatalf("expected 5 LLM calls, got %d", len(client.sent))
	}

	// Round 5's prompt is 3 rounds after the pull, well outside the 2-round
	// RECENT ROUNDS window — the sticky block is the only thing that could
	// still carry it there, and it must carry it whole, tail marker
	// included, not cut at 1500 chars.
	round5Msg := client.sent[4].Messages[0].Content
	if !strings.Contains(round5Msg, "TWE PLAYBOOK DETAIL") {
		t.Errorf("round 5 prompt missing sticky TWE PLAYBOOK DETAIL section")
	}
	if !strings.Contains(round5Msg, "TWE-STATE-001") {
		t.Errorf("round 5 prompt missing pulled TWE id")
	}
	if !strings.Contains(round5Msg, "END-OF-DETAIL-MARKER") {
		t.Errorf("round 5 prompt truncated the pulled detail before its tail marker")
	}
}

// ─── Non-final round soft whitelist ──────────────────────────────────

func TestPlannerRun_MiddleRoundPromptUsesSoftWhitelist(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"read_file","args":{"path":"src/attest.rs","start":1,"end":20}}]}`,
		`{"thought":"r2","actions":[{"name":"ripgrep","args":{"pattern":"Error","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"ok","candidates":[]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	_ = planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-middle",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
	})

	if len(client.sent) < 2 {
		t.Fatalf("expected at least 2 LLM calls, got %d", len(client.sent))
	}
	round2Msg := client.sent[1].Messages[0].Content
	if strings.Contains(round2Msg, "FINAL ROUND") {
		t.Errorf("middle round should NOT contain FINAL ROUND block")
	}
	if !strings.Contains(round2Msg, "PATHS OBSERVED SO FAR") {
		t.Errorf("middle round should contain soft whitelist ('PATHS OBSERVED SO FAR'), got:\n%s", round2Msg)
	}
	if !strings.Contains(round2Msg, "src/attest.rs") {
		t.Errorf("middle round whitelist missing src/attest.rs")
	}
}

// ─── Corrective re-ask on an unparseable reply ───────────────────────

// A model that narrates instead of emitting the required JSON object used to
// kill the entire run on its first slip — seven good rounds discarded because
// the eighth said "Let me continue reading." response_format is not honoured
// on every round by every endpoint, so the planner re-asks once before giving
// up. Observed against glm-5.2 on 2026-07-28: rounds 1-4 parsed, round 5
// returned 387 bytes of prose, run terminated with 0 candidates.
func TestPlannerRun_ReAsksOnceWhenReplyIsNotJSON(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	client := &mockLLM{scripts: []string{
		"I have the PSS branch. Let me continue reading.",
		`{"thought":"recovered","actions":[{"name":"done","args":{"summary":"recovered after a re-ask","candidates":[]}}]}`,
	}}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "reask-001",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: actions.NewDefaultRegistryWithNav(),
		Budget:   defaultTestBudget(),
	})

	if result.Err != nil {
		t.Fatalf("a single unparseable reply must not fail the run: %v", result.Err)
	}
	if client.calls != 2 {
		t.Fatalf("want exactly 2 LLM calls (original + one corrective re-ask), got %d", client.calls)
	}
	retry := client.sent[1].Messages[0].Content
	if !strings.Contains(retry, "YOUR PREVIOUS REPLY WAS REJECTED") {
		t.Error("the re-ask must tell the model its reply was rejected")
	}
	if !strings.Contains(retry, "Let me continue reading") {
		t.Error("the re-ask must quote the rejected reply back so the model can see what was wrong")
	}
	if result.Bundle.PlannerMeta.TerminationReason == "llm_malformed" {
		t.Error("run terminated as malformed even though the re-ask parsed")
	}
	// The round really cost two calls; rounds.jsonl must not under-report it.
	if result.Bundle.PlannerMeta.TokensUsed == 0 {
		t.Error("token accounting lost the re-ask")
	}
}

// Two unparseable replies in a row is a real failure: stop, do not burn the
// whole budget re-asking.
func TestPlannerRun_GivesUpAfterOneFailedReAsk(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	// mockLLM repeats its last script once exhausted, so every reply is prose.
	client := &mockLLM{scripts: []string{"still not json, sorry"}}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "reask-002",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Client:   client,
		Registry: actions.NewDefaultRegistryWithNav(),
		Budget:   defaultTestBudget(),
	})

	if result.Err == nil {
		t.Fatal("two unparseable replies in a row must fail the round")
	}
	if client.calls != 2 {
		t.Fatalf("want exactly 2 calls — one bounded re-ask, not an unbounded loop; got %d", client.calls)
	}
	if result.Bundle.PlannerMeta.TerminationReason != "llm_malformed" {
		t.Errorf("termination_reason = %q, want %q", result.Bundle.PlannerMeta.TerminationReason, "llm_malformed")
	}
}
