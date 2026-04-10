package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

const anthropicVersion = "2023-06-01"

type AnthropicClient struct {
	baseURL     string
	apiKey      string
	model       string
	httpClient  *http.Client
	temperature float64
}

func NewAnthropicClient(cfg config.Config) *AnthropicClient {
	cfg = cfg.WithLLMProviderDefaults()
	return &AnthropicClient{
		baseURL:     strings.TrimRight(cfg.LLMBaseURL, "/"),
		apiKey:      cfg.LLMAPIKey,
		model:       cfg.LLMModel,
		httpClient:  newHTTPClient(cfg.LLMTimeoutSec),
		temperature: cfg.LLMTemp,
	}
}

func (c *AnthropicClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	body := anthropicMessagesRequest{
		Model:       c.model,
		System:      strings.TrimSpace(req.SystemPrompt),
		Messages:    buildAnthropicMessages(req.Messages),
		MaxTokens:   16384,
		Temperature: req.Temperature,
	}
	if body.Temperature == 0.0 {
		body.Temperature = c.temperature
	}
	if len(body.Messages) == 0 {
		body.Messages = []anthropicMessage{{Role: "user", Content: "Hello."}}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("marshal anthropic request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(payload))
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("build anthropic request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("read anthropic response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GenerateResponse{}, fmt.Errorf("anthropic status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	text, err := parseAnthropicResponse(respBody)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("parse anthropic response: %w | raw=%s", err, truncateForError(string(respBody), 300))
	}

	return GenerateResponse{
		Text: text,
		Raw:  string(respBody),
	}, nil
}

type anthropicMessagesRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicMessagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func buildAnthropicMessages(messages []Message) []anthropicMessage {
	out := make([]anthropicMessage, 0, len(messages))
	for _, msg := range messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		switch role {
		case "assistant", "user":
		default:
			role = "user"
		}
		out = append(out, anthropicMessage{
			Role:    role,
			Content: msg.Content,
		})
	}
	return out
}

func parseAnthropicResponse(body []byte) (string, error) {
	var parsed anthropicMessagesResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode json response: %w", err)
	}

	var parts []string
	for _, block := range parsed.Content {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			parts = append(parts, block.Text)
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no text content found in response")
	}
	return strings.Join(parts, ""), nil
}
