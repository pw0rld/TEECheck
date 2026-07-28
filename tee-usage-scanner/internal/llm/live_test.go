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
	runLiveLLMDataSourceTest(t, config.Config{
		LLMProvider:   firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:    os.Getenv("TEECHECK_LLM_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:      os.Getenv("TEECHECK_LLM_MODEL"),
		LLMTimeoutSec: 60,
		LLMTemp:       0.1,
	})
}

func TestLiveGLMDataSource(t *testing.T) {
	runLiveLLMDataSourceTest(t, config.Config{
		LLMProvider:   "glm",
		LLMBaseURL:    firstNonEmptyEnv("TEECHECK_GLM_BASE_URL", "GLM_BASE_URL", "ZAI_BASE_URL"),
		LLMAPIKey:     firstNonEmptyEnv("TEECHECK_GLM_API_KEY", "GLM_API_KEY", "ZAI_API_KEY", "TEECHECK_LLM_API_KEY"),
		LLMModel:      firstNonEmptyEnv("TEECHECK_GLM_MODEL", "GLM_MODEL", "ZAI_MODEL", "TEECHECK_LLM_MODEL"),
		LLMTimeoutSec: 60,
		LLMTemp:       0.1,
	})
}

func runLiveLLMDataSourceTest(t *testing.T, cfg config.Config) {
	t.Helper()

	cfg = cfg.WithLLMProviderDefaults()
	if cfg.LLMAPIKey == "" {
		t.Skipf("%s API key not set, skipping live LLM test", strings.ToUpper(cfg.LLMProvider))
	}

	client := llm.NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.LLMTimeoutSec)*time.Second)
	defer cancel()

	t.Logf("provider=%s base_url=%s model=%s", cfg.LLMProvider, cfg.LLMBaseURL, cfg.LLMModel)

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
			JSONMode:    true,
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
			JSONMode:    true,
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

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
