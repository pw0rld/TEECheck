package verifier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// ─── Fixtures ───────────────────────────────────────────────────────

// repoFixture writes a small Rust file and returns the repo root.
func repoFixture(t *testing.T) (repoRoot, srcPath string) {
	t.Helper()
	repoRoot = t.TempDir()
	srcPath = filepath.Join(repoRoot, "src", "auth.rs")
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "fn check() {\n    // line 2\n    do_thing();\n}\n"
	if err := os.WriteFile(srcPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return repoRoot, srcPath
}

// hypothesisWithFacts builds an artifact with prepared CitedFacts.
func hypothesisWithFacts(facts []citations.CitedFact) artifacts.Hypothesis {
	return artifacts.Hypothesis{
		SchemaVersion: "teecheck.hypothesis.v1",
		CaseID:        "case-001",
		AgentID:       "expert-001",
		Title:         "test",
		CitedFacts:    facts,
	}
}

// ─── Stubs ──────────────────────────────────────────────────────────

type stubLLM struct {
	responseJSON string
	gotRequest   *llm.GenerateRequest
}

func (s *stubLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.gotRequest = &req
	return llm.GenerateResponse{Text: s.responseJSON}, nil
}

type captureRecorder struct {
	events []events.Event
}

func (c *captureRecorder) Emit(e events.Event) error {
	e.Seq = int64(len(c.events) + 1)
	c.events = append(c.events, e)
	return nil
}
func (c *captureRecorder) Close() error { return nil }

// minimalParsedResponse builds a verifier JSON that exercises the
// no-queries success path.
func verifierResponse(t *testing.T, confirmedCited, contradictedCited []citations.CitedFact, status string) string {
	t.Helper()
	body := map[string]any{
		"status":                   status,
		"confirmed_cited_facts":    confirmedCited,
		"contradicted_cited_facts": contradictedCited,
		"confirmed_facts":          []string{},
		"contradictions":           []string{},
		"notes":                    []string{},
		"queries":                  []map[string]string{},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// ─── Investigation knowledge reaches the prompt (2026-07-28) ────────

// sectionBody returns the text under the prompt section whose header
// starts with headerPrefix, up to the next blank line — so the empty
// case is checkable: a header with nothing under it fails, a header
// with "(none)" passes.
func sectionBody(t *testing.T, prompt, headerPrefix string) string {
	t.Helper()
	i := strings.Index(prompt, headerPrefix)
	if i < 0 {
		t.Fatalf("prompt has no section starting %q:\n%s", headerPrefix, prompt)
	}
	rest := prompt[i:]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		t.Fatalf("section %q has no body at all:\n%s", headerPrefix, prompt)
	}
	body := rest[nl+1:]
	if end := strings.Index(body, "\n\n"); end >= 0 {
		body = body[:end]
	}
	return strings.TrimSpace(body)
}

const (
	observedFlowHeader    = "Observed flow ("
	counterEvidenceHeader = "Counter-evidence the Investigator already found ("
)

// The Verifier decides corroborated / contested / inconclusive, and
// arbitrates the Expert against the Challenger. Counter-evidence the
// Planner already recorded is an input to exactly that decision, and the
// traced flow is the chain whose completeness the Arbiter's gate later
// depends on. A field that reached only the Expert would be a partial
// fix.
func TestBuildMemoLLM_PromptCarriesObservedFlowAndCounterEvidence(t *testing.T) {
	repo, _ := repoFixture(t)
	stub := &stubLLM{responseJSON: verifierResponse(t, nil, nil, "inconclusive")}
	bus := agentbus.New(0)

	pack := artifacts.CasePack{
		CaseID: "case-001",
		ObservedFlow: []artifacts.ToolPathStep{{
			Location: artifacts.ToolLocation{Path: "core/tee/tee_rollback.c", StartLine: 91, Symbol: "rollback_check"},
			Kind:     "sink",
			Message:  "OBSERVED-STEP-MARKER",
		}},
		CounterEvidence: []string{"COUNTER-EVIDENCE-MARKER"},
	}
	if _, err := buildMemoLLM(context.Background(), stub, bus, repo, pack,
		artifacts.Hypothesis{}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil); err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}
	prompt := stub.gotRequest.Messages[0].Content

	flow := sectionBody(t, prompt, observedFlowHeader)
	for _, want := range []string{"core/tee/tee_rollback.c:91", "rollback_check", "OBSERVED-STEP-MARKER"} {
		if !strings.Contains(flow, want) {
			t.Errorf("observed-flow section missing %q:\n%s", want, flow)
		}
	}
	if counter := sectionBody(t, prompt, counterEvidenceHeader); !strings.Contains(counter, "COUNTER-EVIDENCE-MARKER") {
		t.Errorf("counter-evidence section missing the marker:\n%s", counter)
	}
}

// to_agent is a closed vocabulary. The arbiter's prompt published it; this
// one did not, and on run 44362-vuln-p9 the verifier spent all four of its
// bus queries asking "fact-layer" — an endpoint that does not exist. Every
// one was refused (four bus_query_failed events), so the Expert/Challenger
// dispute those queries were meant to settle went unanswered and the memo
// came back "contested".
func TestBuildMemoLLM_PromptPublishesTheAgentVocabulary(t *testing.T) {
	repo, _ := repoFixture(t)
	stub := &stubLLM{responseJSON: verifierResponse(t, nil, nil, "inconclusive")}

	bus := agentbus.New(1)
	bus.Register("expert-001", func(context.Context, agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{}, nil
	})
	bus.Register("challenger-001", func(context.Context, agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{}, nil
	})

	if _, err := buildMemoLLM(context.Background(), stub, bus, repo,
		artifacts.CasePack{CaseID: "case-001"}, artifacts.Hypothesis{}, artifacts.Challenge{},
		caseContext{}, "verifier-001", 0, nil, nil); err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}

	sys := stub.gotRequest.SystemPrompt
	for _, name := range []string{"expert-001", "challenger-001"} {
		if !strings.Contains(sys, name) {
			t.Errorf("system prompt must name the registered agent %q — it is the only way "+
				"to_agent's legal values reach the model:\n%s", name, sys)
		}
	}
	if !strings.Contains(sys, "no fact layer") {
		t.Errorf("system prompt must deny the endpoint this agent actually invented:\n%s", sys)
	}
}

func TestBuildMemoLLM_EmptyFlowAndCounterEvidenceRenderCleanly(t *testing.T) {
	repo, _ := repoFixture(t)
	stub := &stubLLM{responseJSON: verifierResponse(t, nil, nil, "inconclusive")}
	bus := agentbus.New(0)

	if _, err := buildMemoLLM(context.Background(), stub, bus, repo, artifacts.CasePack{CaseID: "case-001"},
		artifacts.Hypothesis{}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil); err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}
	prompt := stub.gotRequest.Messages[0].Content

	if got := sectionBody(t, prompt, observedFlowHeader); got != "(none)" {
		t.Errorf("empty observed flow rendered as %q, want %q", got, "(none)")
	}
	if got := sectionBody(t, prompt, counterEvidenceHeader); got != "(none)" {
		t.Errorf("empty counter-evidence rendered as %q, want %q", got, "(none)")
	}
}

// ─── Validation prompt block ────────────────────────────────────────

func TestFormatExpertCitationStatus_ValidStaleUnanchoredUnresolved(t *testing.T) {
	results := []citations.CitationValidation{
		{FactText: "valid claim", Status: citations.StatusValid,
			Cited: []citations.CitedBytes{{File: "x.rs", StartLine: 1, EndLine: 2}}},
		{FactText: "drifted claim", Status: citations.StatusStale,
			Reason: "citation: sha256 drifted: file=x.rs",
			Cited:  []citations.CitedBytes{{File: "x.rs", StartLine: 5, EndLine: 5}}},
		{FactText: "no anchor", Status: citations.StatusUnanchored},
		{FactText: "cannot validate", Status: citations.StatusUnresolved,
			Reason: "repo not available for validation"},
	}
	out := formatExpertCitationStatus(results)
	for _, status := range []string{"valid", "stale", "unanchored", "unresolved"} {
		if !strings.Contains(out, "["+status+"]") {
			t.Errorf("missing [%s] tag in:\n%s", status, out)
		}
	}
	if !strings.Contains(out, "cite: x.rs:1-2") {
		t.Error("citation reference missing for valid fact")
	}
	if !strings.Contains(out, "sha256 drifted") {
		t.Error("stale Reason missing")
	}
}

func TestFormatExpertCitationStatus_EmptyShowsExplicitMarker(t *testing.T) {
	out := formatExpertCitationStatus(nil)
	if !strings.Contains(out, "no expert facts produced") {
		t.Errorf("empty validation should produce explicit marker, got: %q", out)
	}
}

// ─── Validation propagation through buildMemoLLM ────────────────────

func TestBuildMemoLLM_ExpertValidationReachesPromptAndMemo(t *testing.T) {
	repo, _ := repoFixture(t)

	// One valid + one drifted citation on the expert side.
	resolved, err := citations.Resolve(citations.CitedBytes{
		File: "src/auth.rs", StartLine: 1, EndLine: 2,
	}, repo)
	if err != nil {
		t.Fatal(err)
	}
	drifted := resolved
	drifted.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	expertFacts := []citations.CitedFact{
		{Text: "fresh claim", Cited: []citations.CitedBytes{resolved}},
		{Text: "drifted claim", Cited: []citations.CitedBytes{drifted}},
		{Text: "unanchored claim"},
	}
	expertValidation := citations.ValidateFacts(expertFacts, repo)

	stub := &stubLLM{responseJSON: verifierResponse(t, nil, nil, "inconclusive")}
	bus := agentbus.New(0)

	pack := artifacts.CasePack{CaseID: "case-001", Category: "tee", Priority: "high"}
	memo, err := buildMemoLLM(context.Background(), stub, bus, repo,
		pack, hypothesisWithFacts(expertFacts), artifacts.Challenge{}, caseContext{},
		"verifier-001", 0, nil, expertValidation)
	if err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}

	// Prompt must carry the citation status section.
	prompt := stub.gotRequest.Messages[0].Content
	if !strings.Contains(prompt, "EXPERT CITATION STATUS") {
		t.Error("user prompt missing EXPERT CITATION STATUS section")
	}
	if !strings.Contains(prompt, "[valid]") {
		t.Error("prompt missing [valid] tag")
	}
	if !strings.Contains(prompt, "[stale]") {
		t.Error("prompt missing [stale] tag")
	}
	if !strings.Contains(prompt, "[unanchored]") {
		t.Error("prompt missing [unanchored] tag")
	}

	// Memo's ExpertCitationValidation is set BY THE CALLER (RunWithBus
	// /Run set memo.ExpertCitationValidation = expertValidation),
	// so buildMemoLLM does not populate it directly. This test
	// confirms the prompt path; persistence is covered separately.
	_ = memo
}

// ─── Verifier produces its own cited_facts ──────────────────────────

func TestBuildMemoLLM_ResolvesAndFlattensVerifierFacts(t *testing.T) {
	repo, _ := repoFixture(t)

	// Verifier claims one good citation + one bad path.
	good := citations.CitedFact{
		Text: "guard exists at line 1",
		Cited: []citations.CitedBytes{
			{File: "src/auth.rs", StartLine: 1, EndLine: 1},
		},
	}
	badPath := citations.CitedFact{
		Text: "drifted-path claim",
		Cited: []citations.CitedBytes{
			{File: "src/missing.rs", StartLine: 1, EndLine: 1},
		},
	}
	stub := &stubLLM{
		responseJSON: verifierResponse(t,
			[]citations.CitedFact{good},
			[]citations.CitedFact{badPath},
			"corroborated"),
	}
	bus := agentbus.New(0)
	pack := artifacts.CasePack{CaseID: "case-001"}
	memo, err := buildMemoLLM(context.Background(), stub, bus, repo,
		pack, hypothesisWithFacts(nil), artifacts.Challenge{}, caseContext{},
		"verifier-001", 0, nil, nil)
	if err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}

	if len(memo.ConfirmedCitedFacts) != 1 {
		t.Errorf("ConfirmedCitedFacts=%d want 1", len(memo.ConfirmedCitedFacts))
	}
	if len(memo.ConfirmedCitedFacts[0].Cited) != 1 {
		t.Errorf("good fact citation lost: %+v", memo.ConfirmedCitedFacts[0])
	}
	if len(memo.ContradictedCitedFacts) != 1 {
		t.Errorf("ContradictedCitedFacts=%d want 1 (bad-path fact kept with empty Cited)",
			len(memo.ContradictedCitedFacts))
	}
	if len(memo.ContradictedCitedFacts[0].Cited) != 0 {
		t.Errorf("bad-path fact should have empty Cited: %+v", memo.ContradictedCitedFacts[0])
	}

	// Validated text in legacy fields, drifted-path text NOT in
	// the legacy fields (would imply validation it didn't pass).
	hasGoodInConfirmed := false
	for _, s := range memo.ConfirmedFacts {
		if strings.Contains(s, "guard exists") {
			hasGoodInConfirmed = true
		}
	}
	if !hasGoodInConfirmed {
		t.Errorf("validated confirmed text missing from ConfirmedFacts: %v", memo.ConfirmedFacts)
	}
	for _, s := range memo.Contradictions {
		if strings.Contains(s, "drifted-path") {
			t.Errorf("unresolved contradiction text leaked into Contradictions: %q", s)
		}
	}

	// Cited pool is the union of resolved citations.
	if len(memo.Cited) != 1 {
		t.Errorf("Cited pool=%d, want 1 (one good citation)", len(memo.Cited))
	}
}

// ─── Legacy text-only LLM response → Untyped channels (V1.1.2 polish C3) ─

func TestBuildMemoLLM_LegacyTextOnlyLandsInUntypedFields(t *testing.T) {
	// LLM ignored the cited_facts schema and returned legacy
	// text-only confirmed_facts/contradictions. Pre-polish, those
	// strings were folded into memo.ConfirmedFacts/Contradictions
	// (the validated text surface) and arbiter Evidence read them
	// as if validated. Now they must land in
	// UntypedConfirmedFacts / UntypedContradictions instead, with
	// the validated surface staying empty.
	repo, _ := repoFixture(t)
	body := map[string]any{
		"status":          "corroborated",
		"confirmed_facts": []string{"legacy text-only fact"},
		"contradictions":  []string{"legacy contradiction"},
	}
	raw, _ := json.Marshal(body)
	stub := &stubLLM{responseJSON: string(raw)}
	bus := agentbus.New(0)

	memo, err := buildMemoLLM(context.Background(), stub, bus, repo,
		artifacts.CasePack{CaseID: "case-001"},
		hypothesisWithFacts(nil), artifacts.Challenge{}, caseContext{},
		"verifier-001", 0, nil, nil)
	if err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}
	// Validated surface must NOT contain legacy text.
	for _, s := range memo.ConfirmedFacts {
		if strings.Contains(s, "legacy text-only") {
			t.Errorf("legacy text leaked into ConfirmedFacts: %q", s)
		}
	}
	for _, s := range memo.Contradictions {
		if strings.Contains(s, "legacy contradiction") {
			t.Errorf("legacy text leaked into Contradictions: %q", s)
		}
	}
	// Untyped channels must preserve the text.
	if len(memo.UntypedConfirmedFacts) != 1 ||
		!strings.Contains(memo.UntypedConfirmedFacts[0], "legacy text-only") {
		t.Errorf("UntypedConfirmedFacts: %v", memo.UntypedConfirmedFacts)
	}
	if len(memo.UntypedContradictions) != 1 ||
		!strings.Contains(memo.UntypedContradictions[0], "legacy contradiction") {
		t.Errorf("UntypedContradictions: %v", memo.UntypedContradictions)
	}
	// Structured fields stay empty as expected.
	if len(memo.ConfirmedCitedFacts) != 0 {
		t.Errorf("ConfirmedCitedFacts should be empty for legacy response, got %d", len(memo.ConfirmedCitedFacts))
	}
}

// ─── Event emission ─────────────────────────────────────────────────

func TestEmitVerifierClaimEvents_OnePerFactDistinctIDs(t *testing.T) {
	rec := &captureRecorder{}
	memo := artifacts.VerificationMemo{
		CaseID: "case-007",
		ConfirmedCitedFacts: []citations.CitedFact{
			{Text: "c1", Cited: []citations.CitedBytes{{File: "x.rs", StartLine: 1, EndLine: 1, SHA256: "abc", StartByte: 0, EndByte: 4}}},
			{Text: "c2 (unanchored)", Cited: nil},
		},
		ContradictedCitedFacts: []citations.CitedFact{
			{Text: "x1", Cited: []citations.CitedBytes{{File: "y.rs", StartLine: 5, EndLine: 5, SHA256: "def", StartByte: 0, EndByte: 4}}},
		},
	}
	emitVerifierClaimEvents(rec, "run-1", "verifier-001", memo)

	if len(rec.events) != 3 {
		t.Fatalf("emitted %d events, want 3 (2 confirmed + 1 contradicted)", len(rec.events))
	}
	for _, e := range rec.events {
		if e.Type != events.TypeClaimEmitted {
			t.Errorf("event type=%q, want %q", e.Type, events.TypeClaimEmitted)
		}
		if e.Agent != "verifier-001" || e.CaseID != "case-007" {
			t.Errorf("correlation fields wrong: %+v", e)
		}
	}
	// claim_id namespacing: confirmed and contradicted must not
	// collide even though both start at index 1.
	ids := map[string]bool{}
	for _, e := range rec.events {
		if ids[e.ClaimID] {
			t.Errorf("duplicate claim_id: %q", e.ClaimID)
		}
		ids[e.ClaimID] = true
	}
	hasConfirmed := false
	hasContradicted := false
	for id := range ids {
		if strings.Contains(id, "confirmed") {
			hasConfirmed = true
		}
		if strings.Contains(id, "contradicted") {
			hasContradicted = true
		}
	}
	if !hasConfirmed || !hasContradicted {
		t.Errorf("expected both confirmed and contradicted in claim_ids: %v", ids)
	}
}
