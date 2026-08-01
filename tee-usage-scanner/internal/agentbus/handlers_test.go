package agentbus_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

type stubClient struct {
	resp llm.GenerateResponse
	err  error
}

func (s stubClient) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	return s.resp, s.err
}

func TestNewLLMHandler(t *testing.T) {
	handler := agentbus.NewLLMHandler(stubClient{
		resp: llm.GenerateResponse{
			Text: `{"answer":"The check is missing because verify_qe_identity_policy skips timestamp","facts":["verify.rs:42 no nonce"]}`,
		},
	}, "You are the Expert Agent.", 0.2)
	resp, err := handler(context.Background(), agentbus.Query{
		QueryID:   "q-001",
		FromAgent: "verifier-001",
		ToAgent:   "expert-001",
		Kind:      "clarify",
		Question:  "Why is attestation missing?",
		// Evidence is required now: a bus agent has no file access and no
		// tools, so a query without it can only be answered by invention.
		// This test previously asserted the opposite behaviour.
		Evidence: "CasePack: src/verify.rs\nToolFacts: (none)",
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.Answer == "" {
		t.Fatal("expected non-empty answer")
	}
	if len(resp.Facts) == 0 {
		t.Fatal("expected at least one fact")
	}
}

func TestNewToolHandler(t *testing.T) {
	handler := agentbus.NewToolHandler("mapper", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "mapper",
			Answer:    "Found 3 matches",
			Facts:     []string{"verify.rs:10 fn verify_quote", "state.rs:20 fn apply"},
		}, nil
	})

	resp, err := handler(context.Background(), agentbus.Query{
		QueryID:  "q-001",
		ToAgent:  "mapper",
		Kind:     "search",
		Question: "Find verify-related code",
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.FromAgent != "mapper" {
		t.Fatalf("expected from mapper, got %s", resp.FromAgent)
	}
	if len(resp.Facts) != 2 {
		t.Fatalf("expected 2 facts, got %d", len(resp.Facts))
	}
}
