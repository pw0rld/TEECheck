package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

type limitTransport func(*http.Request) (*http.Response, error)

func (f limitTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestPerCallOutputBudget(t *testing.T) {
	for _, transport := range []string{"chat_completions", "responses", "anthropic"} {
		t.Run(transport, func(t *testing.T) {
			for _, configured := range []int{4096, 32768} {
				for _, requested := range []int{512, 8192, 40000, 0} {
					var body map[string]any
					httpClient := &http.Client{Transport: limitTransport(func(r *http.Request) (*http.Response, error) {
						json.NewDecoder(r.Body).Decode(&body)
						response := `{"choices":[{"message":{"content":"{}"}}]}`
						if transport == "responses" {
							response = `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"{}"}]}]}`
						} else if transport == "anthropic" {
							response = `{"content":[{"type":"text","text":"{}"}]}`
						}
						return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(response))}, nil
					})}
					cfg := config.Config{LLMBaseURL: "http://local.invalid", LLMModel: "test", LLMMaxTokens: configured, LLMTransport: transport}
					open := NewOpenAIClient(cfg)
					open.httpClient = httpClient
					var c Client = open
					if transport == "anthropic" {
						a := NewAnthropicClient(cfg)
						a.httpClient = httpClient
						c = a
					}
					_, err := c.Generate(context.Background(), GenerateRequest{Messages: []Message{{Role: "user", Content: "JSON"}}, MaxOutputTokens: requested})
					if err != nil {
						t.Fatal(err)
					}
					field := "max_tokens"
					if transport == "responses" {
						field = "max_output_tokens"
					}
					want := configured
					if requested > 0 && requested < want {
						want = requested
					}
					if body[field] != float64(want) {
						t.Fatalf("%s=%v want %d", field, body[field], want)
					}
				}
			}
		})
	}
}
