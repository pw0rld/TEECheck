package expert

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/tools"
)

// ─── Helpers under test ─────────────────────────────────────────────

// Strict ResolveFacts (V1.1.2 polish C1): partial-failure clears
// the entire Cited list. Comprehensive coverage lives in
// internal/citations/validation_test.go; this thin wrap confirms
// expert calls the same primitive without code-path shenanigans.
func TestResolveFacts_StrictDowngradeOnPartialFailure(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "x.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	in := []citations.CitedFact{
		{Text: "good fact", Cited: []citations.CitedBytes{
			{File: "src/x.rs", StartLine: 1, EndLine: 1},
		}},
		{Text: "partial fact", Cited: []citations.CitedBytes{
			{File: "src/x.rs", StartLine: 2, EndLine: 2}, // would resolve
			{File: "src/missing.rs", StartLine: 1, EndLine: 1},
		}},
		{Text: "  ", Cited: []citations.CitedBytes{
			{File: "src/x.rs", StartLine: 1, EndLine: 1},
		}},
	}
	out, _ := citations.ResolveFacts(in, repo)
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2 (empty-text fact dropped)", len(out))
	}
	if len(out[0].Cited) != 1 {
		t.Errorf("good fact citation lost: %+v", out[0])
	}
	if len(out[1].Cited) != 0 {
		t.Errorf("partial fact: kept=%d, want 0 (strict downgrade)", len(out[1].Cited))
	}
}

func TestFlattenFacts_OnlyValidatedTextEntersSupporting(t *testing.T) {
	resolved := citations.CitedBytes{
		File: "x.rs", StartLine: 1, EndLine: 1,
		StartByte: 0, EndByte: 2, SHA256: "abc",
	}
	in := []citations.CitedFact{
		{Text: "validated", Cited: []citations.CitedBytes{resolved}},
		{Text: "unanchored", Cited: nil},
		// Duplicate citation across two facts — dedupe in pool.
		{Text: "validated 2", Cited: []citations.CitedBytes{resolved}},
	}
	supporting, pool := citations.FlattenFacts(in)

	// Only facts with at least one resolved citation enter
	// SupportingFacts; unanchored is excluded.
	if len(supporting) != 2 {
		t.Errorf("supporting=%v, want 2 entries (unanchored excluded)", supporting)
	}
	for _, s := range supporting {
		if s == "unanchored" {
			t.Errorf("unanchored fact leaked into SupportingFacts")
		}
	}

	// Pool dedupes by (file, start_byte, end_byte, sha256).
	if len(pool) != 1 {
		t.Errorf("pool=%d, want 1 (deduped)", len(pool))
	}
}

func TestFlattenFacts_SkipsUnresolvedEntriesInPool(t *testing.T) {
	in := []citations.CitedFact{
		{Text: "mixed", Cited: []citations.CitedBytes{
			{File: "x.rs", StartLine: 1, EndLine: 1},                 // not resolved
			{File: "x.rs", StartLine: 2, EndLine: 2, SHA256: "xyz",
				StartByte: 0, EndByte: 1},                            // resolved
		}},
	}
	_, pool := citations.FlattenFacts(in)
	if len(pool) != 1 {
		t.Errorf("pool=%d, want 1 (unresolved skipped)", len(pool))
	}
}

// ─── Integration: stub LLM + real fixture repo ──────────────────────

type stubLLM struct {
	responseJSON string
	gotRequest   *llm.GenerateRequest
}

func (s *stubLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.gotRequest = &req
	return llm.GenerateResponse{Text: s.responseJSON}, nil
}

type stubToolAdapter struct{}

func (stubToolAdapter) SearchKeywords(_ context.Context, _ string, _, _ []string, _ int) ([]tools.SearchHit, error) {
	return nil, nil
}

func TestBuildHypothesisLLM_PopulatesCitedFactsAndFlattens(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "auth.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "fn check() {\n    // line 2: missing guard\n    do_thing();\n}\n"
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := map[string]any{
		"title":               "Missing guard in check",
		"summary":             "do_thing called without authorization gate",
		"suspected_issue":     "missing caller binding",
		"missing_obligations": []string{"caller_authorization"},
		"confidence":          "medium",
		"needs_verification":  true,
		"cited_facts": []map[string]any{
			{
				"text": "do_thing is reachable without a guard",
				"cited": []map[string]any{
					{"file": "src/auth.rs", "start_line": 1, "end_line": 4},
				},
			},
			{
				// This one will fail to resolve (file missing).
				"text": "presumed bypass path",
				"cited": []map[string]any{
					{"file": "src/missing.rs", "start_line": 10, "end_line": 12},
				},
			},
			{
				// Asserted with no citation — must stay in
				// CitedFacts but NOT enter SupportingFacts.
				"text":  "free-form claim with no anchor",
				"cited": []map[string]any{},
			},
		},
	}
	respBytes, _ := json.Marshal(resp)

	stub := &stubLLM{responseJSON: string(respBytes)}
	pack := artifacts.CasePack{
		CaseID:        "case-001",
		Category:      "authorization",
		Priority:      "high",
		TargetFiles:   []string{"src/auth.rs"},
		TargetSymbols: []string{"check"},
	}
	h, err := buildHypothesisLLM(context.Background(), stub, stubToolAdapter{}, repo, pack, "expert-001", 0)
	if err != nil {
		t.Fatalf("buildHypothesisLLM: %v", err)
	}

	if len(h.CitedFacts) != 3 {
		t.Fatalf("CitedFacts len = %d, want 3 (all 3 facts kept; bad citations dropped per-fact)", len(h.CitedFacts))
	}
	if len(h.CitedFacts[0].Cited) != 1 || !h.CitedFacts[0].Cited[0].Resolved() {
		t.Errorf("fact[0] citation not resolved: %+v", h.CitedFacts[0])
	}
	if len(h.CitedFacts[1].Cited) != 0 {
		t.Errorf("fact[1] citations should have been dropped: %+v", h.CitedFacts[1])
	}
	if len(h.CitedFacts[2].Cited) != 0 {
		t.Errorf("fact[2] (no anchor) should have empty Cited: %+v", h.CitedFacts[2])
	}

	// SupportingFacts contains ONLY validated fact texts.
	hasValidated := false
	for _, s := range h.SupportingFacts {
		if strings.Contains(s, "do_thing is reachable without a guard") {
			hasValidated = true
		}
		if strings.Contains(s, "presumed bypass path") {
			t.Errorf("unresolved fact leaked into SupportingFacts: %q", s)
		}
		if strings.Contains(s, "free-form claim with no anchor") {
			t.Errorf("unanchored fact leaked into SupportingFacts: %q", s)
		}
	}
	if !hasValidated {
		t.Errorf("validated fact missing from SupportingFacts: %v", h.SupportingFacts)
	}

	// Cited pool is the union of resolved citations (1 here).
	if len(h.Cited) != 1 {
		t.Errorf("Cited pool len=%d, want 1", len(h.Cited))
	}
	if h.Cited[0].SHA256 == "" {
		t.Error("Cited pool entry not resolved")
	}

	// Prompt actually instructed the model to produce cited_facts.
	if !strings.Contains(stub.gotRequest.Messages[0].Content, "cited_facts") {
		t.Error("user prompt did not request cited_facts")
	}
}

// ─── Untyped facts separation (V1.1.2 polish C2) ────────────────────

func TestBuildHypothesisLLM_LegacySupportingFactsGoToUntypedFacts(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src", "x.rs")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("fn one() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// LLM returns BOTH structured cited_facts AND legacy
	// supporting_facts. Pre-V1.1.2-polish the legacy strings would
	// have been mixed into SupportingFacts as "validated"; now they
	// must land in UntypedFacts instead.
	resp := map[string]any{
		"title":           "x",
		"summary":         "x",
		"suspected_issue": "x",
		"cited_facts": []map[string]any{
			{"text": "anchored fact", "cited": []map[string]any{
				{"file": "src/x.rs", "start_line": 1, "end_line": 1},
			}},
		},
		"supporting_facts":   []string{"legacy unstructured claim"},
		"confidence":         "low",
		"needs_verification": false,
	}
	respBytes, _ := json.Marshal(resp)
	stub := &stubLLM{responseJSON: string(respBytes)}

	pack := artifacts.CasePack{CaseID: "case-001"}
	h, err := buildHypothesisLLM(context.Background(), stub, stubToolAdapter{}, repo, pack, "expert-001", 0)
	if err != nil {
		t.Fatalf("buildHypothesisLLM: %v", err)
	}

	// SupportingFacts must contain ONLY the anchored claim text.
	for _, s := range h.SupportingFacts {
		if strings.Contains(s, "legacy unstructured claim") {
			t.Errorf("legacy text leaked into SupportingFacts: %q", s)
		}
	}
	hasAnchored := false
	for _, s := range h.SupportingFacts {
		if strings.Contains(s, "anchored fact") {
			hasAnchored = true
		}
	}
	if !hasAnchored {
		t.Errorf("anchored fact missing from SupportingFacts: %v", h.SupportingFacts)
	}

	// UntypedFacts must contain the legacy string.
	hasLegacy := false
	for _, s := range h.UntypedFacts {
		if strings.Contains(s, "legacy unstructured claim") {
			hasLegacy = true
		}
	}
	if !hasLegacy {
		t.Errorf("legacy string missing from UntypedFacts: %v", h.UntypedFacts)
	}
}

// ─── Event emission ─────────────────────────────────────────────────

type captureRecorder struct {
	events []events.Event
}

func (c *captureRecorder) Emit(e events.Event) error {
	e.Seq = int64(len(c.events) + 1)
	c.events = append(c.events, e)
	return nil
}
func (c *captureRecorder) Close() error { return nil }

func TestEmitClaimEvents_OnePerCitedFact(t *testing.T) {
	rec := &captureRecorder{}
	h := artifacts.Hypothesis{
		CaseID: "case-007",
		CitedFacts: []citations.CitedFact{
			{Text: "fact 1", Cited: []citations.CitedBytes{
				{File: "x.rs", StartLine: 1, EndLine: 2,
					StartByte: 0, EndByte: 4, SHA256: "abc"},
			}},
			{Text: "fact 2 (unanchored)", Cited: nil},
		},
	}
	emitClaimEvents(rec, "run-1", "expert-001", h)

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d, want 2 (one per CitedFact, even unanchored)", len(rec.events))
	}
	for i, e := range rec.events {
		if e.Type != events.TypeClaimEmitted {
			t.Errorf("events[%d].Type=%q, want %q", i, e.Type, events.TypeClaimEmitted)
		}
		if e.Agent != "expert-001" {
			t.Errorf("events[%d].Agent=%q", i, e.Agent)
		}
		if e.CaseID != "case-007" {
			t.Errorf("events[%d].CaseID=%q", i, e.CaseID)
		}
		if e.ClaimID == "" {
			t.Errorf("events[%d].ClaimID empty", i)
		}
	}
	if rec.events[0].ClaimID == rec.events[1].ClaimID {
		t.Error("claim_ids not unique within case")
	}
	if len(rec.events[0].Cited) != 1 {
		t.Errorf("event[0].Cited=%d, want 1", len(rec.events[0].Cited))
	}
	if len(rec.events[1].Cited) != 0 {
		t.Errorf("event[1].Cited=%d, want 0 (unanchored)", len(rec.events[1].Cited))
	}
}
