package arbiter

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// TestBuildPacket_SurfacesUntypedSections confirms the packet
// rendering catches both untyped surfaces a human reviewer would
// otherwise miss when scanning the packet markdown alone.
func TestBuildPacket_SurfacesUntypedSections(t *testing.T) {
	pack := artifacts.CasePack{CaseID: "case-001", Category: "tee", Priority: "high"}
	h := artifacts.Hypothesis{
		Title:        "test hypothesis",
		Summary:      "summary",
		UntypedFacts: []string{"tool-hit-line-42"},
	}
	c := artifacts.Challenge{}
	m := artifacts.VerificationMemo{
		Status:                "inconclusive",
		UntypedConfirmedFacts: []string{"legacy-confirm-text"},
		UntypedContradictions: []string{"legacy-contradict-text"},
	}
	item := artifacts.FindingItem{Status: "needs_review", Confidence: "low"}
	sections := buildSections(pack, h, c, m, caseContext{}, artifacts.ChallengerIndependentView{})
	body := buildPacket(pack, h, c, m, item, sections)

	for _, want := range []string{
		"Unanchored context",
		"[unanchored] tool-hit-line-42",
		"Unanchored confirmed",
		"[unanchored] legacy-confirm-text",
		"Unanchored contradictions",
		"[unanchored] legacy-contradict-text",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("packet missing %q\n--- packet ---\n%s", want, body)
		}
	}
}

// TestTaggedJoin pins the prompt-formatting helper used by
// arbitrateLLM so untyped items reach the LLM with explicit tags
// rather than as a bare strings list.
func TestTaggedJoin(t *testing.T) {
	if got := taggedJoin(nil, "[unanchored]"); got != "(none)" {
		t.Errorf("nil: %q want (none)", got)
	}
	if got := taggedJoin([]string{"a", "b"}, "[unanchored]"); got != "[unanchored] a | [unanchored] b" {
		t.Errorf("got %q", got)
	}
}

// CitedFact is referenced from imported package; touch it once so
// imports stay tidy if test variants are added.
var _ = citations.CitedFact{}

// ─── Investigation knowledge reaches the prompt (2026-07-28) ────────

type stubLLM struct {
	responseJSON string
	gotRequest   *llm.GenerateRequest
}

func (s *stubLLM) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.gotRequest = &req
	return llm.GenerateResponse{Text: s.responseJSON}, nil
}

const arbiterResponseJSON = `{"status":"needs_review","severity":"low","confidence":"low","summary":"s","evidence":[],"review_packet_markdown":"m","queries":[]}`

// sectionBody returns the text under the prompt section whose header
// starts with headerPrefix, up to the next blank line, so the empty case
// is checkable rather than merely absent.
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

// The vocabulary sentence moved to agentbus so the verifier could share it
// (it had none, and spent every bus query on the nonexistent "fact-layer").
// Nothing covered the arbiter's copy either, so the move could have dropped
// it here without a single test noticing.
func TestArbitrateLLM_PromptPublishesTheAgentVocabulary(t *testing.T) {
	stub := &stubLLM{responseJSON: arbiterResponseJSON}
	bus := agentbus.New(1)
	bus.Register("expert-001", func(context.Context, agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{}, nil
	})

	if _, _, err := arbitrateLLM(context.Background(), stub, bus, artifacts.CasePack{CaseID: "case-001"},
		artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{},
		caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0); err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
	}
	if sys := stub.gotRequest.SystemPrompt; !strings.Contains(sys, "expert-001") {
		t.Errorf("system prompt must name the registered agent:\n%s", sys)
	}
}

// The Arbiter's own mechanical gate (attackChainComplete) decides whether
// "confirmed" wording is allowed, and its prompt asks the model to judge
// the same chain. Handing it the traced path and the Planner's
// counter-evidence is the difference between judging the chain and
// judging three agents' summaries of it.
func TestArbitrateLLM_PromptCarriesObservedFlowAndCounterEvidence(t *testing.T) {
	stub := &stubLLM{responseJSON: arbiterResponseJSON}
	pack := artifacts.CasePack{
		CaseID: "case-001",
		ObservedFlow: []artifacts.ToolPathStep{{
			Location: artifacts.ToolLocation{Path: "core/tee/tee_rollback.c", StartLine: 91, Symbol: "rollback_check"},
			Message:  "OBSERVED-STEP-MARKER",
		}},
		CounterEvidence: []string{"COUNTER-EVIDENCE-MARKER"},
	}

	if _, _, err := arbitrateLLM(context.Background(), stub, agentbus.New(0), pack,
		artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{},
		caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0); err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
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

func TestArbitrateLLM_EmptyFlowAndCounterEvidenceRenderCleanly(t *testing.T) {
	stub := &stubLLM{responseJSON: arbiterResponseJSON}
	if _, _, err := arbitrateLLM(context.Background(), stub, agentbus.New(0), artifacts.CasePack{CaseID: "case-001"},
		artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{},
		caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0); err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
	}
	prompt := stub.gotRequest.Messages[0].Content

	if got := sectionBody(t, prompt, observedFlowHeader); got != "(none)" {
		t.Errorf("empty observed flow rendered as %q, want %q", got, "(none)")
	}
	if got := sectionBody(t, prompt, counterEvidenceHeader); got != "(none)" {
		t.Errorf("empty counter-evidence rendered as %q, want %q", got, "(none)")
	}
}
