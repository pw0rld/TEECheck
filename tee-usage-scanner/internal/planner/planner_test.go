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

func setupFixtureRepo(t *testing.T) (repoRoot, runDir, catalogPath string) {
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

	catalogDir := filepath.Join(t.TempDir(), "sinks")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	catalogPath = filepath.Join(catalogDir, "rust.json")
	catalogJSON := `{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "remote attestation chain",
      "categories": [
        {
          "id": "verify",
          "description": "verify entry points",
          "match": { "kind": "symbol", "symbols": ["*::verify_quote"] },
          "severity_hint": "high"
        }
      ]
    }
  ]
}`
	if err := os.WriteFile(catalogPath, []byte(catalogJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return repoRoot, runDir, catalogPath
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
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"look at the catalog","actions":[{"name":"sink_catalog_lookup","args":{"scope":"*"}}]}`,
		`{"thought":"ripgrep for verify","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"read it","actions":[{"name":"read_file","args":{"path":"src/attest.rs","start":1,"end":20}}]}`,
		`{"thought":"found a candidate","actions":[{"name":"done","args":{"summary":"verify_quote lacks freshness","candidates":[{"id":"c1","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["No nonce check"],"confidence":0.8}]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:       "test-happy",
		RepoRoot:    repoRoot,
		RunDir:      runDir,
		Profile:     planner.PromptProfile{Focus: "tee", Languages: []string{"rust"}},
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

	if _, err := os.Stat(filepath.Join(runDir, "04_planner", "evidence_bundle.json")); err != nil {
		t.Errorf("evidence_bundle.json missing: %v", err)
	}
}

// ─── Budget exhaustion ───────────────────────────────────────────────

func TestPlannerRun_BudgetExhaustedByRounds(t *testing.T) {
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"sink_catalog_lookup","args":{"scope":"*"}}]}`,
		`{"thought":"r2","actions":[{"name":"sink_catalog_lookup","args":{"scope":"attestation"}}]}`,
		`{"thought":"r3","actions":[{"name":"sink_catalog_lookup","args":{"scope":"attestation.verify"}}]}`,
		`{"thought":"r4","actions":[{"name":"ripgrep","args":{"pattern":"verify","globs":["*.rs"]}}]}`,
		`{"thought":"r5","actions":[{"name":"ripgrep","args":{"pattern":"quote","globs":["*.rs"]}}]}`,
		`{"thought":"r6","actions":[{"name":"ripgrep","args":{"pattern":"attest","globs":["*.rs"]}}]}`,
		`{"thought":"r7","actions":[{"name":"ripgrep","args":{"pattern":"key","globs":["*.rs"]}}]}`,
		`{"thought":"r8","actions":[{"name":"ripgrep","args":{"pattern":"seal","globs":["*.rs"]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

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
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	dup := `{"thought":"same again","actions":[{"name":"ripgrep","args":{"pattern":"verify","globs":["*.rs"]}}]}`
	client := &mockLLM{scripts: []string{
		dup,
		dup,
		dup,
		`{"thought":"stopping","actions":[{"name":"done","args":{"summary":"done","candidates":[]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

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
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`this is not JSON at all`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

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
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"mixed","candidates":[` +
			`{"id":"real","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["real"]},` +
			`{"id":"fake","kind":"attestation","priority":"high","paths":["sgx/svc/src/key.rs"],"symbols":["ghost"],"why_selected":["hallucinated"]}` +
			`]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

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
}

// ─── Observed paths in prompt ────────────────────────────────────────

func TestPlannerRun_FinalRoundPromptIncludesObservedPaths(t *testing.T) {
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"read_file","args":{"path":"src/attest.rs","start":1,"end":20}}]}`,
		`{"thought":"final","actions":[{"name":"done","args":{"summary":"ok","candidates":[]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

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

// ─── Non-final round soft whitelist ──────────────────────────────────

func TestPlannerRun_MiddleRoundPromptUsesSoftWhitelist(t *testing.T) {
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"r1","actions":[{"name":"read_file","args":{"path":"src/attest.rs","start":1,"end":20}}]}`,
		`{"thought":"r2","actions":[{"name":"ripgrep","args":{"pattern":"Error","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"ok","candidates":[]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

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
