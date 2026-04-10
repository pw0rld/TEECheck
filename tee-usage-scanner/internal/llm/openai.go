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

type OpenAIClient struct {
	baseURL     string
	apiKey      string
	model       string
	httpClient  *http.Client
	temperature float64
}

func NewOpenAIClient(cfg config.Config) *OpenAIClient {
	cfg = cfg.WithLLMProviderDefaults()
	return &OpenAIClient{
		baseURL:     strings.TrimRight(cfg.LLMBaseURL, "/"),
		apiKey:      cfg.LLMAPIKey,
		model:       cfg.LLMModel,
		httpClient:  newHTTPClient(cfg.LLMTimeoutSec),
		temperature: cfg.LLMTemp,
	}
}

func (c *OpenAIClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	body := openAIChatRequest{
		Model:       c.model,
		Messages:    buildMessages(req.SystemPrompt, req.Messages),
		Temperature: req.Temperature,
		Stream:      false,
		MaxTokens:   16384,
	}
	if body.Temperature == 0.0 {
		body.Temperature = c.temperature
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
	httpReq.Header.Set("Accept", "application/json")
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

	text, err := parseOpenAIResponse(resp.Header.Get("Content-Type"), respBody)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("parse llm response: %w | raw=%s", err, truncateForError(string(respBody), 300))
	}

	return GenerateResponse{
		Text: text,
		Raw:  string(respBody),
	}, nil
}

type openAIChatRequest struct {
	Model          string                `json:"model"`
	Messages       []map[string]string   `json:"messages"`
	Temperature    float64               `json:"temperature"`
	Stream         bool                  `json:"stream"`
	MaxTokens      int                   `json:"max_tokens,omitempty"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIResponseFormat struct {
	Type string `json:"type"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content any `json:"content"`
		} `json:"message"`
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		Text string `json:"text"`
	} `json:"choices"`
}

func parseOpenAIResponse(contentType string, body []byte) (string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", fmt.Errorf("empty response body")
	}
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") || strings.HasPrefix(trimmed, "data:") {
		return parseOpenAIStream(trimmed)
	}

	var parsed openAIChatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode json response: %w", err)
	}
	text := extractOpenAIText(parsed)
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("no text content found in response")
	}
	return text, nil
}

func parseOpenAIStream(raw string) (string, error) {
	var content strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}

		var chunk openAIChatResponse
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		content.WriteString(extractOpenAIText(chunk))
	}
	if content.Len() == 0 {
		return "", fmt.Errorf("no text content found in stream response")
	}
	return content.String(), nil
}

func extractOpenAIText(resp openAIChatResponse) string {
	for _, choice := range resp.Choices {
		if text := normalizeOpenAIContent(choice.Message.Content); text != "" {
			return text
		}
		if strings.TrimSpace(choice.Text) != "" {
			return choice.Text
		}
		if strings.TrimSpace(choice.Delta.Content) != "" {
			return choice.Delta.Content
		}
	}
	return ""
}

func normalizeOpenAIContent(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		var parts []string
		for _, item := range typed {
			switch entry := item.(type) {
			case map[string]any:
				if text, ok := entry["text"].(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, text)
					continue
				}
				if text, ok := entry["content"].(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "")
	case map[string]any:
		if text, ok := typed["text"].(string); ok {
			return text
		}
		if text, ok := typed["content"].(string); ok {
			return text
		}
	}
	return ""
}

func truncateForError(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
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
