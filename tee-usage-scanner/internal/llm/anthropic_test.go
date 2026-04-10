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
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(bytes.NewBufferString(`{
				"content": [
					{"type":"text","text":"{\"ok\":true}"}
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
	if got.MaxTokens != 16384 {
		t.Fatalf("unexpected max_tokens: %d", got.MaxTokens)
	}
	if len(got.Messages) != 1 || got.Messages[0].Role != "user" || got.Messages[0].Content != "hello" {
		t.Fatalf("unexpected messages payload: %+v", got.Messages)
	}
}
