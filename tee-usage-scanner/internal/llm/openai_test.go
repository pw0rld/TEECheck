package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

// A reasoning model that spends its whole completion budget on thinking
// returns finish_reason "length" with empty content. Reported as "no text
// content found in response" — which is what happened on 2026-07-29 — it
// reads as a parser bug and sends the reader looking in the wrong place.
// The error must name the cause and the knob that fixes it.
func TestParseOpenAIResponse_BudgetExhaustedByReasoning(t *testing.T) {
	body := []byte(`{"choices":[{"finish_reason":"length","index":0,` +
		`"message":{"content":"","reasoning_content":"Let me analyze this carefully..."}}],` +
		`"usage":{"prompt_tokens":9000,"completion_tokens":16384,` +
		`"completion_tokens_details":{"reasoning_tokens":16384}}}`)

	_, _, err := parseOpenAIResponse("application/json", body)
	if err == nil {
		t.Fatal("an empty completion must be an error")
	}
	for _, want := range []string{"finish_reason=length", "16384", "reasoning", "llm-max-tokens"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q so the cause and the fix are both visible; got: %v", want, err)
		}
	}
}

// An empty completion for any OTHER reason keeps the original message —
// blaming the token budget for an unrelated empty reply would be its own
// wrong diagnosis.
func TestParseOpenAIResponse_EmptyForOtherReasonsKeepsOldMessage(t *testing.T) {
	body := []byte(`{"choices":[{"finish_reason":"stop","message":{"content":""}}]}`)
	_, _, err := parseOpenAIResponse("application/json", body)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "no text content found") {
		t.Fatalf("want the generic message for a non-length finish, got: %v", err)
	}
	if strings.Contains(err.Error(), "llm-max-tokens") {
		t.Fatalf("must not blame the token budget for an unrelated empty reply: %v", err)
	}
}

// The budget must be configurable and must reach the wire. It was hardcoded
// at 16384 in both clients, so a model that needed more could not be given
// more without recompiling.
func TestOpenAIClient_MaxTokensComesFromConfig(t *testing.T) {
	var got struct {
		MaxTokens int `json:"max_tokens"`
	}
	client := NewOpenAIClient(config.Config{
		LLMBaseURL: "https://example.test", LLMAPIKey: "k", LLMModel: "m",
		LLMTimeoutSec: 5, LLMMaxTokens: 99001,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return &http.Response{StatusCode: http.StatusOK,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewBufferString(`{"choices":[{"message":{"content":"ok"}}]}`))}, nil
	})}
	if _, err := client.Generate(context.Background(), GenerateRequest{
		Messages: []Message{{Role: "user", Content: "hi"}}}); err != nil {
		t.Fatal(err)
	}
	if got.MaxTokens != 99001 {
		t.Fatalf("max_tokens = %d, want the configured 99001", got.MaxTokens)
	}
}

// A hand-built Config with no budget must still produce a usable request.
func TestOpenAIClient_ZeroMaxTokensFallsBackToDefault(t *testing.T) {
	var got struct {
		MaxTokens int `json:"max_tokens"`
	}
	client := NewOpenAIClient(config.Config{
		LLMBaseURL: "https://example.test", LLMAPIKey: "k", LLMModel: "m", LLMTimeoutSec: 5,
	})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		return &http.Response{StatusCode: http.StatusOK,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(bytes.NewBufferString(`{"choices":[{"message":{"content":"ok"}}]}`))}, nil
	})}
	_, _ = client.Generate(context.Background(), GenerateRequest{Messages: []Message{{Role: "user", Content: "hi"}}})
	if got.MaxTokens != config.DefaultLLMMaxTokens {
		t.Fatalf("max_tokens = %d, want the default %d", got.MaxTokens, config.DefaultLLMMaxTokens)
	}
}
