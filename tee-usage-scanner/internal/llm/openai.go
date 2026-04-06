package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

type OpenAIClient struct {
	baseURL     string
	apiKey      string
	model       string
	httpClient  *http.Client
	temperature float64
}

func NewOpenAIClient(cfg config.Config) *OpenAIClient {
	return &OpenAIClient{
		baseURL: strings.TrimRight(cfg.LLMBaseURL, "/"),
		apiKey:  cfg.LLMAPIKey,
		model:   cfg.LLMModel,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.LLMTimeoutSec) * time.Second,
		},
		temperature: cfg.LLMTemp,
	}
}

func (c *OpenAIClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	body := map[string]any{
		"model":       c.model,
		"messages":    buildMessages(req.SystemPrompt, req.Messages),
		"temperature": req.Temperature,
	}
	if body["temperature"] == 0.0 {
		body["temperature"] = c.temperature
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("marshal llm request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("build llm request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("read llm response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GenerateResponse{}, fmt.Errorf("llm status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return GenerateResponse{}, fmt.Errorf("parse llm response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return GenerateResponse{}, fmt.Errorf("llm response contained no choices")
	}
	return GenerateResponse{
		Text: parsed.Choices[0].Message.Content,
		Raw:  string(respBody),
	}, nil
}

func buildMessages(systemPrompt string, messages []Message) []map[string]string {
	out := make([]map[string]string, 0, len(messages)+1)
	if strings.TrimSpace(systemPrompt) != "" {
		out = append(out, map[string]string{
			"role":    "system",
			"content": systemPrompt,
		})
	}
	for _, msg := range messages {
		out = append(out, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}
	return out
}
