package agentbus

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

// An agent with no evidence must refuse, not answer.
//
// NewLLMHandler gave every bus agent a ~200-byte system prompt and the
// question text: no case pack, no ToolFacts, no file access. On 2026-08-01
// the arbiter asked reviewer-001 to trace callers of shdr_load_pub_key. It
// answered — inventing ta_open(), ta_load(), syscall_load_subkey() and
// tee_rollback_cache_update(), none of which exist in the 2706-file tree —
// and that answer alone flipped the arbiter from needs_review to
// no_issue_observed, overriding a CodeQL ToolFact.
//
// A prompt instruction would not hold: it already said "cite by fact_id, do
// not restate as your own finding" and was overridden anyway. So the refusal
// is structural.
func TestNewLLMHandler_RefusesWithoutEvidence(t *testing.T) {
	client := &llmtest.FakeClient{Default: `{"answer":"sure, here is a call graph","facts":["invented"]}`}
	h := NewLLMHandler(client, "You are the Reviewer Agent.", 0.2)

	_, err := h(context.Background(), Query{
		FromAgent: "arbiter-001", ToAgent: "reviewer-001",
		Question: "trace the callers of shdr_load_pub_key",
	})
	if err == nil {
		t.Fatal("an agent with no case evidence must refuse, not answer")
	}
	if !strings.Contains(err.Error(), "evidence") {
		t.Errorf("the refusal must say why: %v", err)
	}
	if len(client.Calls) != 0 {
		t.Errorf("the model must not be called at all; calls = %d", len(client.Calls))
	}
}

// With evidence, it answers, and the evidence reaches the prompt.
func TestNewLLMHandler_ForwardsEvidence(t *testing.T) {
	client := &llmtest.FakeClient{Default: `{"answer":"ok","facts":[]}`}
	h := NewLLMHandler(client, "You are the Reviewer Agent.", 0.2)

	resp, err := h(context.Background(), Query{
		FromAgent: "arbiter-001", ToAgent: "reviewer-001",
		Question: "does the version propagate?",
		Evidence: "ToolFacts:\n- [fact-1] status=success at core/crypto/signed_hdr.c:262: producer never propagates 'version'",
	})
	if err != nil {
		t.Fatalf("with evidence it must answer: %v", err)
	}
	if resp.Answer != "ok" {
		t.Errorf("Answer = %q", resp.Answer)
	}
	if len(client.Calls) != 1 {
		t.Fatalf("model calls = %d, want 1", len(client.Calls))
	}
	sent := client.Calls[0]
	joined := sent.SystemPrompt
	for _, m := range sent.Messages {
		joined += m.Content
	}
	if !strings.Contains(joined, "signed_hdr.c:262") {
		t.Errorf("the evidence must reach the model:\n%s", joined)
	}
	// And it must be told the evidence is the whole of what it can see.
	if !strings.Contains(joined, "only") && !strings.Contains(joined, "no other") {
		t.Errorf("the prompt must bound what the agent may claim:\n%s", sent.SystemPrompt)
	}
}
