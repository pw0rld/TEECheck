package stats_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/stats"
)

func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollect_EmptyRunDirReturnsBlankStats(t *testing.T) {
	dir := t.TempDir()
	rs, err := stats.Collect(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rs.Planner.Present {
		t.Error("expected planner absent")
	}
	if rs.Arbiter.Present {
		t.Error("expected arbiter absent")
	}
	if rs.Overall.PipelineYield != 0 {
		t.Error("expected zero yield for empty run")
	}
}

func TestCollect_MissingRunDirErrors(t *testing.T) {
	if _, err := stats.Collect("/definitely/does/not/exist", ""); err == nil {
		t.Error("expected error for missing run dir")
	}
}

func TestCollect_FullSyntheticRunAlignsVerifierAndArbiter(t *testing.T) {
	dir := t.TempDir()
	repo := t.TempDir()

	// Repo side: one real file containing one real symbol, one
	// fake path will be invented in the bundle to exercise the
	// hallucination counter.
	real := filepath.Join(repo, "src", "attestation.rs")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("fn verify_report() { /* real */ }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Planner bundle: 2 candidates. First is valid (path + symbol
	// both exist), second has a hallucinated path.
	bundle := artifacts.EvidenceBundle{
		SchemaVersion: "teecheck.evidence_bundle.v1",
		RunID:         "test-001",
		PlannerMeta: artifacts.PlannerMeta{
			RoundsUsed:        4,
			RoundsBudget:      8,
			TokensUsed:        1000,
			WallClockMs:       5000,
			TerminationReason: "llm_done",
		},
		Candidates: []artifacts.Candidate{
			{
				ID:      "cand-1",
				Kind:    "attestation",
				Paths:   []string{"src/attestation.rs"},
				Symbols: []string{"verify_report"},
			},
			{
				ID:      "cand-2",
				Kind:    "key_management",
				Paths:   []string{"src/fake.rs"}, // doesn't exist
				Symbols: []string{"nonexistent"},
			},
		},
	}
	writeJSON(t, filepath.Join(dir, "04_planner", "evidence_bundle.json"), bundle)

	// 3-line JSONL: 2 rounds with real tokens, 1 with zero (provider didn't report)
	roundsFile := filepath.Join(dir, "04_planner", "rounds.jsonl")
	if err := os.MkdirAll(filepath.Dir(roundsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	roundsData := `{"round":1,"thought":"t1","actions":[{"name":"ripgrep","args":{}}],"observations":[],"tokens_in":100,"tokens_out":50,"wall_clock_ms":500}
{"round":2,"thought":"t2","actions":[{"name":"read_file","args":{}}],"observations":[],"tokens_in":200,"tokens_out":80,"wall_clock_ms":800}
`
	if err := os.WriteFile(roundsFile, []byte(roundsData), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2 case packs
	for i, sym := range []string{"verify_report", "nonexistent"} {
		pack := artifacts.CasePack{
			CaseID:        "case-00" + itoa(i+1),
			TargetSymbols: []string{sym},
			Snippets: []artifacts.PromptSnippet{
				{Path: "src/attestation.rs", StartLine: 1, EndLine: 1, Content: "fn verify_report() {}"},
			},
			ExpectedObligations: []string{"attestation-identity-verification"},
		}
		writeJSON(t, filepath.Join(dir, "03_cases", "case-00"+itoa(i+1)+".json"), pack)
	}

	// 2 hypotheses
	for i := 1; i <= 2; i++ {
		h := artifacts.Hypothesis{
			CaseID:          "case-00" + itoa(i),
			Summary:         "Missing freshness check in src/attestation.rs:12",
			SuspectedIssue:  "Replay resistance is absent.",
			SupportingFacts: []string{"observed at src/attestation.rs:12"},
			Confidence:      "medium",
		}
		writeJSON(t, filepath.Join(dir, "04_expert", "hypothesis-00"+itoa(i)+".json"), h)
	}

	// 2 challenges (one with counter args, one empty → rubber stamp)
	writeJSON(t, filepath.Join(dir, "05_challenger", "challenge-001.json"),
		artifacts.Challenge{CaseID: "case-001", CounterArguments: []string{"actually caller handles this"}})
	writeJSON(t, filepath.Join(dir, "05_challenger", "challenge-002.json"),
		artifacts.Challenge{CaseID: "case-002", CounterArguments: nil, ReviewerStance: "neutral"})

	// 2 verifier memos — one corroborated, one inconclusive
	writeJSON(t, filepath.Join(dir, "06_verifier", "verify-001.json"),
		artifacts.VerificationMemo{CaseID: "case-001", Status: "corroborated", ConfirmedFacts: []string{"a", "b"}})
	writeJSON(t, filepath.Join(dir, "06_verifier", "verify-002.json"),
		artifacts.VerificationMemo{CaseID: "case-002", Status: "inconclusive"})

	// arbiter findings keyed by slice_id == case_id
	findings := artifacts.Findings{
		Findings: []artifacts.FindingItem{
			{FindingID: "f1", SliceID: "case-001", Status: "needs_review", Severity: "high", Confidence: "medium"},
			{FindingID: "f2", SliceID: "case-002", Status: "needs_review", Severity: "low", Confidence: "low"},
		},
	}
	writeJSON(t, filepath.Join(dir, "07_arbiter", "findings.json"), findings)

	// Run the collector
	rs, err := stats.Collect(dir, repo)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// Planner assertions
	if !rs.Planner.Present {
		t.Fatal("expected planner present")
	}
	if rs.Planner.CandidateCount != 2 {
		t.Errorf("candidate_count=%d want 2", rs.Planner.CandidateCount)
	}
	if rs.Planner.PathValidityRate != 0.5 {
		t.Errorf("path_validity=%v want 0.5", rs.Planner.PathValidityRate)
	}
	if len(rs.Planner.HallucinatedPaths) != 1 {
		t.Errorf("hallucinated_paths=%v", rs.Planner.HallucinatedPaths)
	}
	if rs.Planner.TokensUsed != 1000 {
		t.Errorf("tokens_used=%d want 1000", rs.Planner.TokensUsed)
	}
	if got := rs.Planner.ActionMix["ripgrep"]; got != 1 {
		t.Errorf("action_mix[ripgrep]=%d want 1", got)
	}
	if got := rs.Planner.ActionMix["read_file"]; got != 1 {
		t.Errorf("action_mix[read_file]=%d want 1", got)
	}
	if len(rs.Planner.TokensByRound) != 2 {
		t.Errorf("tokens_by_round len=%d want 2", len(rs.Planner.TokensByRound))
	}
	if rs.Planner.TokensByRound[0] != 150 {
		t.Errorf("tokens_by_round[0]=%d want 150", rs.Planner.TokensByRound[0])
	}

	// Cases: symbol coverage = 1/2 (case-001 has sym in snippet, case-002 does not)
	if rs.Cases.CaseCount != 2 {
		t.Errorf("case_count=%d want 2", rs.Cases.CaseCount)
	}
	if rs.Cases.SymbolCoverageRate != 0.5 {
		t.Errorf("symbol_coverage=%v want 0.5", rs.Cases.SymbolCoverageRate)
	}
	if rs.Cases.ObligationsAttached != 2 {
		t.Errorf("obligations_attached=%d want 2", rs.Cases.ObligationsAttached)
	}

	// Expert: both hypotheses cite src/attestation.rs:12 → citation_rate=1.0
	if rs.Expert.CitationRate != 1.0 {
		t.Errorf("citation_rate=%v want 1.0", rs.Expert.CitationRate)
	}

	// Challenger: 1 non-rubber-stamp (case-001) out of 2
	if rs.Challenger.NonRubberStampRate != 0.5 {
		t.Errorf("non_rubber_stamp=%v want 0.5", rs.Challenger.NonRubberStampRate)
	}

	// Verifier: 1 corroborated, 1 inconclusive → rate = 0.5
	if rs.Verifier.CorroborationRate != 0.5 {
		t.Errorf("corroboration_rate=%v want 0.5", rs.Verifier.CorroborationRate)
	}

	// Arbiter: both findings needs_review
	// verifier case-001 = corroborated → matches "needs_review" per verifierStatusMatches (true)
	// verifier case-002 = inconclusive → does NOT match needs_review (false)
	// agreement rate should be 0.5, matched via slice_id
	if rs.Arbiter.VerifierAgreementRate != 0.5 {
		t.Errorf("verifier_agreement=%v want 0.5", rs.Arbiter.VerifierAgreementRate)
	}
	if rs.Arbiter.FindingCount != 2 {
		t.Errorf("finding_count=%d want 2", rs.Arbiter.FindingCount)
	}

	// Overall
	if rs.Overall.Dropoff.Corroborated != 1 {
		t.Errorf("dropoff.corroborated=%d want 1", rs.Overall.Dropoff.Corroborated)
	}
	if rs.Overall.PipelineYield != 0.5 {
		t.Errorf("pipeline_yield=%v want 0.5", rs.Overall.PipelineYield)
	}
}

// tiny itoa to avoid strconv import in a test file
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}
