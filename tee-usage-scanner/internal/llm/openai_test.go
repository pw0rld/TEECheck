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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestOpenAIClientGenerate(t *testing.T) {
	type requestBody struct {
		Model          string `json:"model"`
		Stream         bool   `json:"stream"`
		ResponseFormat *struct {
			Type string `json:"type"`
		} `json:"response_format"`
	}

	var got requestBody
	client := NewOpenAIClient(config.Config{
		LLMBaseURL:    "https://example.test",
		LLMAPIKey:     "test-key",
		LLMModel:      "gpt-test",
		LLMTimeoutSec: 5,
		LLMTemp:       0.1,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %q", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"choices":[{"message":{"content":"{\"ok\":true}"}}]}`)),
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
	if resp.Text == "" {
		t.Fatal("expected text in response")
	}
	if got.Stream {
		t.Fatal("expected non-stream request")
	}
	// JSONMode must reach the wire. Fourteen agents set it and every one of
	// them parses the reply with ExtractJSONObject; a model that narrates
	// instead of emitting an object fails the stage outright. This assertion
	// previously required the opposite — it pinned the fact that nothing
	// consumed the flag, rather than any decision to omit it.
	if got.ResponseFormat == nil {
		t.Fatal("JSONMode was set but no response_format reached the request")
	}
	if got.ResponseFormat.Type != "json_object" {
		t.Fatalf("response_format type = %q, want %q", got.ResponseFormat.Type, "json_object")
	}
}

// A caller that does NOT ask for JSON must not get response_format — some
// OpenAI-compatible endpoints reject the field, so it is sent only on request.
func TestOpenAIClientGenerate_NoJSONModeSendsNoResponseFormat(t *testing.T) {
	type requestBody struct {
		ResponseFormat *struct {
			Type string `json:"type"`
		} `json:"response_format"`
	}
	var got requestBody
	client := NewOpenAIClient(config.Config{
		LLMBaseURL: "https://example.test", LLMAPIKey: "test-key",
		LLMModel: "gpt-test", LLMTimeoutSec: 5, LLMTemp: 0.1,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"choices":[{"message":{"content":"plain text"}}]}`)),
		}, nil
	})}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Messages: []Message{{Role: "user", Content: "hello"}},
	}); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if got.ResponseFormat != nil {
		t.Fatalf("response_format must be absent without JSONMode, got %+v", got.ResponseFormat)
	}
}
