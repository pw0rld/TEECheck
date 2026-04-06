package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func TestOpenAIClientGenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"ok\":true}"}}]}`))
	}))
	defer srv.Close()

	client := NewOpenAIClient(config.Config{
		LLMBaseURL:    srv.URL,
		LLMAPIKey:     "test-key",
		LLMModel:      "gpt-test",
		LLMTimeoutSec: 5,
		LLMTemp:       0.1,
	})

	resp, err := client.Generate(context.Background(), GenerateRequest{
		SystemPrompt: "system",
		Messages: []Message{
			{Role: "user", Content: "hello"},
		},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if resp.Text == "" {
		t.Fatal("expected text in response")
	}
}
