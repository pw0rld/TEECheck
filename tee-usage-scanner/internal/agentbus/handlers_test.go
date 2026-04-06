package agentbus_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func TestNewLLMHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{
					"content": `{"answer":"The check is missing because verify_qe_identity_policy skips timestamp","facts":["verify.rs:42 no nonce"]}`,
				}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOpenAIClient(config.Config{
		LLMBaseURL:    srv.URL,
		LLMAPIKey:     "test-key",
		LLMModel:      "test-model",
		LLMTimeoutSec: 5,
		LLMTemp:       0.2,
	})

	handler := agentbus.NewLLMHandler(client, "You are the Expert Agent.", 0.2)
	resp, err := handler(context.Background(), agentbus.Query{
		QueryID:   "q-001",
		FromAgent: "verifier-001",
		ToAgent:   "expert-001",
		Kind:      "clarify",
		Question:  "Why is attestation missing?",
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
