// internal/llm/live_test.go
package llm_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func TestLiveLLMDataSource(t *testing.T) {
	apiKey := os.Getenv("TEECHECK_LLM_API_KEY")
	if apiKey == "" {
		t.Skip("TEECHECK_LLM_API_KEY not set, skipping live LLM test")
	}
	baseURL := os.Getenv("TEECHECK_LLM_BASE_URL")
	if baseURL == "" {
		t.Skip("TEECHECK_LLM_BASE_URL not set, skipping live LLM test")
	}
	model := os.Getenv("TEECHECK_LLM_MODEL")
	if model == "" {
		t.Skip("TEECHECK_LLM_MODEL not set, skipping live LLM test")
	}

	client := llm.NewOpenAIClient(config.Config{
		LLMBaseURL:    baseURL,
		LLMAPIKey:     apiKey,
		LLMModel:      model,
		LLMTimeoutSec: 30,
		LLMTemp:       0.1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("BasicConnectivity", func(t *testing.T) {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: "You are a helpful assistant. Respond with exactly one word.",
			Messages: []llm.Message{
				{Role: "user", Content: "Say hello."},
			},
			Temperature: 0.0,
		})
		if err != nil {
			t.Fatalf("LLM request failed: %v", err)
		}
		if resp.Text == "" {
			t.Fatal("LLM returned empty response")
		}
		t.Logf("Basic connectivity OK, response: %q", resp.Text)
	})

	t.Run("JSONOutput", func(t *testing.T) {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: "You are a JSON generator. Return exactly one JSON object, no other text.",
			Messages: []llm.Message{
				{Role: "user", Content: `Return a JSON object with fields: answer (string), facts (array of strings). Topic: "why is code review important?"`},
			},
			Temperature: 0.0,
		})
		if err != nil {
			t.Fatalf("LLM request failed: %v", err)
		}

		text := strings.TrimSpace(resp.Text)
		var parsed struct {
			Answer string   `json:"answer"`
			Facts  []string `json:"facts"`
		}
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			if idx := strings.Index(text, "{"); idx >= 0 {
				if end := strings.LastIndex(text, "}"); end > idx {
					text = text[idx : end+1]
					err = json.Unmarshal([]byte(text), &parsed)
				}
			}
			if err != nil {
				t.Fatalf("LLM response is not valid JSON: %v\nRaw: %s", err, resp.Text)
			}
		}
		if parsed.Answer == "" {
			t.Fatal("LLM returned empty answer field")
		}
		t.Logf("JSON output OK, answer: %q, facts: %v", parsed.Answer, parsed.Facts)
	})

	t.Run("AgentStyleQuery", func(t *testing.T) {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: `You are the Expert Agent in TEECheck. Another agent asks you a question about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).`,
			Messages: []llm.Message{
				{Role: "user", Content: `Agent verifier-001 asks (clarify):
Why do you suspect the attestation check is incomplete?

Additional context: The function verify_qe_identity_policy in verify.rs does not appear to validate a timestamp or nonce.`},
			},
			Temperature: 0.2,
		})
		if err != nil {
			t.Fatalf("LLM request failed: %v", err)
		}

		var parsed struct {
			Answer string   `json:"answer"`
			Facts  []string `json:"facts"`
		}
		text := resp.Text
		if idx := strings.Index(text, "{"); idx >= 0 {
			if end := strings.LastIndex(text, "}"); end > idx {
				text = text[idx : end+1]
			}
		}
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatalf("Failed to parse agent response as JSON: %v\nRaw: %s", err, resp.Text)
		}
		if parsed.Answer == "" {
			t.Fatal("Agent returned empty answer")
		}
		t.Logf("Agent query OK, answer length: %d chars, facts: %d", len(parsed.Answer), len(parsed.Facts))
	})
}
