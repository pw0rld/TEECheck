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

func TestDeepSeekChatPayloadTemperatureAndBudgets(t *testing.T) {
	for _, tc := range []struct {
		model, effort   string
		wantTemperature bool
		wantBudget      int
	}{
		{"deepseek-chat", "", true, 8192},
		{"deepseek-reasoner", "", false, 32768},
		{"deepseek-flash", "", false, 32768},
		{"deepseek-v4-pro", "high", false, 32768},
		{"deepseek-flash", "none", true, 32768},
		{"custom-reason-model", "", true, 32768},
	} {
		t.Run(tc.model+tc.effort, func(t *testing.T) {
			client := NewOpenAIClient(config.Config{LLMProvider: config.LLMProviderDeepSeek, LLMModel: tc.model, LLMReasoningEffort: tc.effort})
			var got map[string]any
			client.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/v1/chat/completions" {
					t.Fatalf("endpoint=%s", req.URL.Path)
				}
				if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"ok"}}]}`))}, nil
			})}
			_, err := client.Generate(context.Background(), GenerateRequest{Messages: []Message{{Role: "user", Content: "hello"}}})
			if err != nil {
				t.Fatal(err)
			}
			_, hasTemperature := got["temperature"]
			if hasTemperature != tc.wantTemperature {
				t.Fatalf("temperature presence=%v wanted=%v", hasTemperature, tc.wantTemperature)
			}
			if int(got["max_tokens"].(float64)) != tc.wantBudget {
				t.Fatalf("max_tokens=%v", got["max_tokens"])
			}
			if tc.effort != "" && got["reasoning_effort"] != tc.effort {
				t.Fatalf("reasoning_effort=%v", got["reasoning_effort"])
			}
		})
	}
}

func TestOrdinaryChatStillSendsZeroTemperature(t *testing.T) {
	client := NewOpenAIClient(config.Config{LLMBaseURL: "https://example.test", LLMModel: "ordinary"})
	client.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var got map[string]any
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		value, present := got["temperature"]
		if !present || value != float64(0) {
			t.Fatalf("ordinary zero temperature lost: %v", got)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"ok"}}]}`))}, nil
	})}
	if _, err := client.Generate(context.Background(), GenerateRequest{Messages: []Message{{Role: "user", Content: "hello"}}}); err != nil {
		t.Fatal(err)
	}
}
