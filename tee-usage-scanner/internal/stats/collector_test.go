package stats_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
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

	// Expert: hypotheses don't carry typed Cited fields here
	// (legacy shape), so the typed citation_rate is 0.
	// citation_validity_rate is also 0 (no citations to validate).
	if rs.Expert.CitationRate != 0.0 {
		t.Errorf("citation_rate=%v want 0.0 (no Cited fields → typed rate is zero)", rs.Expert.CitationRate)
	}
	if rs.Expert.CitationValidityRate != 0.0 {
		t.Errorf("citation_validity_rate=%v want 0.0", rs.Expert.CitationValidityRate)
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

	// Source: legacy run with no events.jsonl → artifacts everywhere.
	if rs.Source != "artifacts" {
		t.Errorf("rs.Source=%q want artifacts", rs.Source)
	}
	if rs.Planner.Source != "artifacts" {
		t.Errorf("planner.source=%q want artifacts", rs.Planner.Source)
	}
}

// TestCollect_PrefersEventsOverArtifacts seeds both an evidence
// bundle and an events.jsonl with conflicting numbers and verifies
// the planner stats fold from events. Bundle-only fields (candidates,
// path validity, termination reason) still come from the bundle.
func TestCollect_PrefersEventsOverArtifacts(t *testing.T) {
	dir := t.TempDir()
	repo := t.TempDir()

	// Repo with a single real file so path validity stays measurable.
	real := filepath.Join(repo, "src", "x.rs")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("fn x() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Bundle reports tokens=99, rounds=99 — wrong values, the events
	// fold should override them.
	bundle := artifacts.EvidenceBundle{
		SchemaVersion: "teecheck.evidence_bundle.v1",
		RunID:         "test-events",
		PlannerMeta: artifacts.PlannerMeta{
			RoundsUsed:        99,
			RoundsBudget:      8,
			TokensUsed:        99,
			TerminationReason: "llm_done",
		},
		Candidates: []artifacts.Candidate{
			{ID: "c1", Paths: []string{"src/x.rs"}, Symbols: []string{"x"}},
		},
	}
	writeJSON(t, filepath.Join(dir, "04_planner", "evidence_bundle.json"), bundle)

	// rounds.jsonl with stale data — events should win.
	roundsFile := filepath.Join(dir, "04_planner", "rounds.jsonl")
	_ = os.MkdirAll(filepath.Dir(roundsFile), 0o755)
	_ = os.WriteFile(roundsFile,
		[]byte(`{"round":1,"actions":[{"name":"stale","args":{}}],"observations":[],"tokens_in":1,"tokens_out":1}`+"\n"),
		0o644)

	// events.jsonl: 2 rounds, planner-001 agent, real tool calls,
	// real token totals. We hand-craft these instead of using the
	// recorder to keep this test focused on the fold logic.
	eventsLines := []string{
		`{"seq":1,"time":"2026-04-25T10:00:00Z","type":"run_started","run_id":"test-events"}`,
		`{"seq":2,"time":"2026-04-25T10:00:01Z","type":"planner_round_started","run_id":"test-events","agent":"planner-001","round":1}`,
		`{"seq":3,"time":"2026-04-25T10:00:02Z","type":"llm_call_completed","run_id":"test-events","agent":"planner-001","round":1,"tokens_in":300,"tokens_out":100}`,
		`{"seq":4,"time":"2026-04-25T10:00:03Z","type":"tool_call_completed","run_id":"test-events","agent":"planner-001","round":1,"tool_name":"ripgrep","tool_ok":true,"tool_duration_ms":42}`,
		`{"seq":5,"time":"2026-04-25T10:00:04Z","type":"tool_call_completed","run_id":"test-events","agent":"planner-001","round":1,"tool_name":"read_file","tool_ok":true,"tool_duration_ms":12}`,
		`{"seq":6,"time":"2026-04-25T10:00:05Z","type":"planner_round_completed","run_id":"test-events","agent":"planner-001","round":1,"action_count":2,"observation_count":2}`,
		`{"seq":7,"time":"2026-04-25T10:00:06Z","type":"planner_round_started","run_id":"test-events","agent":"planner-001","round":2}`,
		`{"seq":8,"time":"2026-04-25T10:00:07Z","type":"llm_call_completed","run_id":"test-events","agent":"planner-001","round":2,"tokens_in":200,"tokens_out":50}`,
		`{"seq":9,"time":"2026-04-25T10:00:08Z","type":"tool_call_completed","run_id":"test-events","agent":"planner-001","round":2,"tool_name":"done","tool_ok":true}`,
		`{"seq":10,"time":"2026-04-25T10:00:09Z","type":"planner_round_completed","run_id":"test-events","agent":"planner-001","round":2,"action_count":1,"observation_count":1}`,
		`{"seq":11,"time":"2026-04-25T10:00:10Z","type":"run_completed","run_id":"test-events","reason":"completed"}`,
		// non-planner llm event must NOT pollute planner tokens
		`{"seq":12,"time":"2026-04-25T10:00:11Z","type":"llm_call_completed","run_id":"test-events","agent":"expert-001","tokens_in":9999,"tokens_out":9999}`,
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"),
		[]byte(joinNL(eventsLines)), 0o644); err != nil {
		t.Fatal(err)
	}

	rs, err := stats.Collect(dir, repo)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	if rs.Planner.Source != "events" {
		t.Errorf("planner.source=%q want events", rs.Planner.Source)
	}
	// expert event must not leak into planner tokens.
	if rs.Planner.TokensUsed != 650 {
		t.Errorf("tokens_used=%d want 650 (300+100+200+50)", rs.Planner.TokensUsed)
	}
	if rs.Planner.RoundsUsed != 2 {
		t.Errorf("rounds_used=%d want 2", rs.Planner.RoundsUsed)
	}
	// Bundle-derived fields still come from the bundle.
	if rs.Planner.RoundsBudget != 8 {
		t.Errorf("rounds_budget=%d want 8 (from bundle)", rs.Planner.RoundsBudget)
	}
	if rs.Planner.TerminationReason != "llm_done" {
		t.Errorf("termination=%q want llm_done", rs.Planner.TerminationReason)
	}
	if rs.Planner.CandidateCount != 1 {
		t.Errorf("candidate_count=%d want 1", rs.Planner.CandidateCount)
	}
	if got := rs.Planner.ActionMix["ripgrep"]; got != 1 {
		t.Errorf("action_mix[ripgrep]=%d want 1", got)
	}
	if got := rs.Planner.ActionMix["read_file"]; got != 1 {
		t.Errorf("action_mix[read_file]=%d want 1", got)
	}
	if got := rs.Planner.ActionMix["done"]; got != 1 {
		t.Errorf("action_mix[done]=%d want 1", got)
	}
	if got := rs.Planner.ActionMix["stale"]; got != 0 {
		t.Errorf("rounds.jsonl 'stale' action leaked into events fold: got %d", got)
	}
	// tokens_by_round[0] = 400 (round 1: 300+100), [1] = 250 (round 2: 200+50)
	if len(rs.Planner.TokensByRound) != 2 {
		t.Fatalf("tokens_by_round len=%d want 2", len(rs.Planner.TokensByRound))
	}
	if rs.Planner.TokensByRound[0] != 400 {
		t.Errorf("tokens_by_round[0]=%d want 400", rs.Planner.TokensByRound[0])
	}
	if rs.Planner.TokensByRound[1] != 250 {
		t.Errorf("tokens_by_round[1]=%d want 250", rs.Planner.TokensByRound[1])
	}

	// No other stages present; rs.Source ends up "events" since
	// planner is the only present stage and it folded from events.
	if rs.Source != "events" {
		t.Errorf("rs.Source=%q want events", rs.Source)
	}
}

// TestCollect_MixedSourceWhenOtherStagesPresent verifies that a run
// with events.jsonl AND artifact-only downstream stages reports
// rs.Source = "mixed".
func TestCollect_MixedSourceWhenOtherStagesPresent(t *testing.T) {
	dir := t.TempDir()
	repo := t.TempDir()

	real := filepath.Join(repo, "x.rs")
	_ = os.WriteFile(real, []byte("fn x() {}\n"), 0o644)

	bundle := artifacts.EvidenceBundle{
		SchemaVersion: "teecheck.evidence_bundle.v1",
		RunID:         "mixed",
		PlannerMeta:   artifacts.PlannerMeta{RoundsUsed: 1, RoundsBudget: 1, TerminationReason: "llm_done"},
		Candidates:    []artifacts.Candidate{{ID: "c1", Paths: []string{"x.rs"}}},
	}
	writeJSON(t, filepath.Join(dir, "04_planner", "evidence_bundle.json"), bundle)

	// Minimal events.jsonl with one round so planner folds from events.
	eventsBody := `{"seq":1,"time":"2026-04-25T10:00:00Z","type":"planner_round_completed","run_id":"mixed","agent":"planner-001","round":1}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(eventsBody), 0o644); err != nil {
		t.Fatal(err)
	}

	// One artifact-only stage downstream.
	writeJSON(t, filepath.Join(dir, "07_arbiter", "findings.json"),
		artifacts.Findings{Findings: []artifacts.FindingItem{{FindingID: "f1", SliceID: "case-1"}}})

	rs, err := stats.Collect(dir, repo)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rs.Planner.Source != "events" {
		t.Errorf("planner.source=%q want events", rs.Planner.Source)
	}
	if rs.Source != "mixed" {
		t.Errorf("rs.Source=%q want mixed (planner from events, arbiter from artifacts)", rs.Source)
	}
}

// TestCollect_TypedCitations exercises the byte-citation path:
// hypotheses with Cited entries get scored by validating against
// real repo bytes, not by regex-matching their prose.
func TestCollect_TypedCitations(t *testing.T) {
	dir := t.TempDir()
	repo := t.TempDir()

	// Real source file we'll cite.
	src := filepath.Join(repo, "src", "x.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "fn a() {}\nfn b() {}\nfn c() {}\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Resolve a real citation we'll then bake into a hypothesis.
	good, err := citations.Resolve(citations.CitedBytes{
		File: "src/x.rs", StartLine: 2, EndLine: 2,
	}, repo)
	if err != nil {
		t.Fatalf("resolve good: %v", err)
	}

	// Hypothesis 1: one valid citation. Counts toward both rates.
	writeJSON(t, filepath.Join(dir, "04_expert", "hypothesis-001.json"),
		artifacts.Hypothesis{CaseID: "case-001", Cited: []citations.CitedBytes{good}})

	// Hypothesis 2: one drifted citation. Doesn't count toward
	// CitationRate; the citation also doesn't count toward
	// CitationValidityRate's numerator (but does toward denominator).
	drifted := good
	drifted.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	writeJSON(t, filepath.Join(dir, "04_expert", "hypothesis-002.json"),
		artifacts.Hypothesis{CaseID: "case-002", Cited: []citations.CitedBytes{drifted}})

	// Hypothesis 3: no citations at all. Doesn't count toward
	// either rate's numerator; doesn't add to validity denominator.
	writeJSON(t, filepath.Join(dir, "04_expert", "hypothesis-003.json"),
		artifacts.Hypothesis{CaseID: "case-003"})

	rs, err := stats.Collect(dir, repo)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// 1 of 3 hypotheses had a valid cite → 0.33...
	if rs.Expert.CitationRate < 0.33 || rs.Expert.CitationRate > 0.34 {
		t.Errorf("citation_rate=%v want ~0.33 (1 of 3 hypotheses cited validly)", rs.Expert.CitationRate)
	}
	// 1 of 2 attempted citations validated → 0.5
	if rs.Expert.CitationValidityRate != 0.5 {
		t.Errorf("citation_validity_rate=%v want 0.5 (1 valid, 1 drifted)", rs.Expert.CitationValidityRate)
	}
}

// TestCollect_TypedCitationsWithoutRepoIsZero confirms the
// well-defined behavior when stats is asked to collect without a
// repo checkout: typed citations cannot be validated, so both rates
// are zero rather than the regex-era false-positive readings.
func TestCollect_TypedCitationsWithoutRepoIsZero(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "04_expert", "hypothesis-001.json"),
		artifacts.Hypothesis{
			CaseID: "case-001",
			Cited: []citations.CitedBytes{
				{File: "x.rs", StartLine: 1, EndLine: 1, SHA256: "deadbeef"},
			},
		})

	rs, err := stats.Collect(dir, "")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rs.Expert.CitationRate != 0 {
		t.Errorf("citation_rate=%v want 0 (no repo to validate against)", rs.Expert.CitationRate)
	}
	if rs.Expert.CitationValidityRate != 0 {
		t.Errorf("citation_validity_rate=%v want 0", rs.Expert.CitationValidityRate)
	}
}

// TestCollect_ReviewLabels exercises Phase 1 review-labels:
// review_records.jsonl drives TP/FP/NMC counts, and case packs +
// findings.json supply the slicing dimensions.
func TestCollect_ReviewLabels(t *testing.T) {
	dir := t.TempDir()
	repo := t.TempDir()

	bundle := artifacts.EvidenceBundle{
		SchemaVersion: "teecheck.evidence_bundle.v1",
		PlannerMeta:   artifacts.PlannerMeta{TerminationReason: "llm_done"},
		Candidates:    []artifacts.Candidate{{ID: "c1"}, {ID: "c2"}, {ID: "c3"}},
	}
	writeJSON(t, filepath.Join(dir, "04_planner", "evidence_bundle.json"), bundle)

	for i, cat := range []string{"attestation", "boundary", "attestation"} {
		pack := artifacts.CasePack{CaseID: "case-00" + itoa(i+1), Category: cat}
		writeJSON(t, filepath.Join(dir, "03_cases", "case-00"+itoa(i+1)+".json"), pack)
	}

	findings := artifacts.Findings{
		Findings: []artifacts.FindingItem{
			{FindingID: "case-001", SliceID: "case-001", Status: "needs_review", Severity: "high",
				Evidence: []string{"VALIDATED claim", "[unanchored] tool hit"}},
			{FindingID: "case-002", SliceID: "case-002", Status: "needs_review", Severity: "low",
				Evidence: []string{"[unanchored] background only"}},
			{FindingID: "case-003", SliceID: "case-003", Status: "no_issue_observed", Severity: "low",
				Evidence: []string{"VALIDATED other"}},
		},
	}
	writeJSON(t, filepath.Join(dir, "07_arbiter", "findings.json"), findings)

	jsonlPath := filepath.Join(dir, "08_review", "review_records.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(jsonlPath, os.O_CREATE|os.O_WRONLY, 0o644)
	enc := json.NewEncoder(f)
	for _, rec := range []artifacts.ReviewRecord{
		{CaseID: "case-001", FindingID: "case-001", Verdict: artifacts.VerdictTruePositive, ReviewedAt: "t"},
		{CaseID: "case-002", FindingID: "case-002", Verdict: artifacts.VerdictFalsePositive, FPReason: artifacts.FPWrongLayer, ReviewedAt: "t"},
		{CaseID: "case-003", FindingID: "case-003", Verdict: artifacts.VerdictNeedsMoreContext, ReviewedAt: "t"},
	} {
		_ = enc.Encode(rec)
	}
	_ = f.Close()

	rs, err := stats.Collect(dir, repo)
	if err != nil {
		t.Fatal(err)
	}
	r := rs.Review
	if !r.Present {
		t.Fatal("Review not present")
	}
	if r.TotalReviewed != 3 || r.TPCount != 1 || r.FPCount != 1 || r.NMCCount != 1 {
		t.Errorf("counts: total=%d TP=%d FP=%d NMC=%d", r.TotalReviewed, r.TPCount, r.FPCount, r.NMCCount)
	}
	if r.FPRate != 0.5 {
		t.Errorf("FPRate=%v want 0.5", r.FPRate)
	}
	if r.FPReasons[artifacts.FPWrongLayer] != 1 {
		t.Errorf("FPReasons[wrong_layer]=%d want 1", r.FPReasons[artifacts.FPWrongLayer])
	}
	if att := r.ByCategory["attestation"]; att.Total != 2 || att.TP != 1 {
		t.Errorf("ByCategory[attestation]=%+v", att)
	}
	if bnd := r.ByCategory["boundary"]; bnd.FP != 1 || bnd.FPRate != 1.0 {
		t.Errorf("ByCategory[boundary]=%+v", bnd)
	}
	if nr := r.ByArbiterStatus["needs_review"]; nr.TP != 1 || nr.FP != 1 || nr.FPRate != 0.5 {
		t.Errorf("ByArbiterStatus[needs_review]=%+v", nr)
	}
	if val := r.ByCitationValidity["validated"]; val.TP != 1 || val.NMC != 1 {
		t.Errorf("ByCitationValidity[validated]=%+v", val)
	}
	if una := r.ByCitationValidity["unanchored"]; una.FP != 1 || una.FPRate != 1.0 {
		t.Errorf("ByCitationValidity[unanchored]=%+v want FP=1 rate=1.0", una)
	}
}

func TestCollect_ReviewAbsent(t *testing.T) {
	rs, err := stats.Collect(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if rs.Review.Present {
		t.Error("Review.Present=true on empty run")
	}
}

func TestCollect_ReviewLegacyVerdicts(t *testing.T) {
	dir := t.TempDir()
	jsonlPath := filepath.Join(dir, "08_review", "review_records.jsonl")
	_ = os.MkdirAll(filepath.Dir(jsonlPath), 0o755)
	body := `{"case_id":"x","finding_id":"x","verdict":"confirmed","reviewed_at":"t"}` + "\n" +
		`{"case_id":"y","finding_id":"y","verdict":"dismissed","reviewed_at":"t"}` + "\n"
	_ = os.WriteFile(jsonlPath, []byte(body), 0o644)
	rs, err := stats.Collect(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if rs.Review.TPCount != 1 {
		t.Errorf("legacy 'confirmed' should map to TP, got %d", rs.Review.TPCount)
	}
	if rs.Review.FPCount != 1 {
		t.Errorf("legacy 'dismissed' should map to FP, got %d", rs.Review.FPCount)
	}
}

func joinNL(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
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
