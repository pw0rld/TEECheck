package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func TestAnthropicClientGenerateGLM(t *testing.T) {
	type requestBody struct {
		Model       string  `json:"model"`
		System      string  `json:"system"`
		MaxTokens   int     `json:"max_tokens"`
		Temperature float64 `json:"temperature"`
		Messages    []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}

	var got requestBody
	client := NewAnthropicClient(config.Config{
		LLMProvider:   "glm",
		LLMAPIKey:     "test-key",
		LLMTimeoutSec: 5,
		LLMTemp:       0.1,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/api/anthropic/v1/messages" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if key := r.Header.Get("x-api-key"); key != "test-key" {
			t.Fatalf("unexpected x-api-key header: %q", key)
		}
		if version := r.Header.Get("anthropic-version"); version != anthropicVersion {
			t.Fatalf("unexpected anthropic-version header: %q", version)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		// A prefilled assistant turn is NOT echoed back: the reply is the
		// continuation only. Returning a whole object here would have made
		// the prefill invisible to this test, which is how the missing
		// wiring survived — the old decode struct had no field for it
		// either, so the request half was unobservable too.
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(bytes.NewBufferString(`{
				"content": [
					{"type":"text","text":"\"ok\":true}"}
				]
			}`)),
		}, nil
	})}

	resp, err := client.Generate(context.Background(), GenerateRequest{
		SystemPrompt: "system",
		Messages: []Message{
			{Role: "user", Content: "hello"},
		},
		JSONMode: true,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if resp.Text != `{"ok":true}` {
		t.Fatalf("unexpected response text: %q", resp.Text)
	}
	if got.Model != "glm-4.7" {
		t.Fatalf("expected default GLM model, got %q", got.Model)
	}
	if got.System != "system" {
		t.Fatalf("unexpected system prompt: %q", got.System)
	}
	// The budget is no longer hardcoded: a Config with no LLMMaxTokens
	// falls back to the package default rather than to a literal that only
	// this assertion knew about.
	if got.MaxTokens != config.DefaultLLMMaxTokens {
		t.Fatalf("max_tokens = %d, want the default %d", got.MaxTokens, config.DefaultLLMMaxTokens)
	}
	// JSONMode must reach the wire. The Messages API has no response_format,
	// so it arrives as a trailing assistant prefill — without it, "JSON
	// mode" on this path is only a request in the prompt that the model is
	// free to ignore, which is how a live run died on round 1.
	if len(got.Messages) != 2 {
		t.Fatalf("JSONMode was set but no prefill turn reached the request: %+v", got.Messages)
	}
	if got.Messages[1].Role != "assistant" || got.Messages[1].Content != "{" {
		t.Fatalf("prefill turn = %+v, want assistant with content \"{\"", got.Messages[1])
	}
	if got.Messages[0].Role != "user" || got.Messages[0].Content != "hello" {
		t.Fatalf("unexpected messages payload: %+v", got.Messages)
	}
}

// A caller that does not ask for JSON must get no prefill — a forced "{"
// would corrupt any reply that is legitimately prose.
func TestAnthropicClientGenerate_NoJSONModeSendsNoPrefill(t *testing.T) {
	type requestBody struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	var got requestBody
	client := NewAnthropicClient(config.Config{
		LLMProvider: "glm", LLMAPIKey: "test-key", LLMTimeoutSec: 5, LLMTemp: 0.1,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"content":[{"type":"text","text":"plain prose"}]}`)),
		}, nil
	})}

	resp, err := client.Generate(context.Background(), GenerateRequest{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("no JSONMode, so no prefill turn: %+v", got.Messages)
	}
	// And the reply must not gain a stray brace.
	if resp.Text != "plain prose" {
		t.Fatalf("resp.Text = %q, want the reply unmodified", resp.Text)
	}
}

// Prefill is honoured only intermittently — glm-5.2 was observed both
// continuing the object and ignoring the prefill to open its own ```json
// fence. Prepending a brace to the second shape would corrupt a reply the
// extractor can otherwise recover, so the restore must be conditional.
func TestRestorePrefill(t *testing.T) {
	for _, tc := range []struct {
		name, continuation, want string
	}{
		{"honoured", `"ok":true}`, `{"ok":true}`},
		{"honoured with leading space", ` "ok":true}`, `{ "ok":true}`},
		{"ignored, opened its own object", `{"ok":true}`, `{"ok":true}`},
		{"ignored, opened a fence", "```json\n{\"ok\":true}\n```", "```json\n{\"ok\":true}\n```"},
		{"ignored, fence after a newline", "\n```json\n{}\n```", "\n```json\n{}\n```"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := restorePrefill(tc.continuation); got != tc.want {
				t.Fatalf("restorePrefill(%q) = %q, want %q", tc.continuation, got, tc.want)
			}
		})
	}
}
