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
	baseURL         string
	apiKey          string
	model           string
	httpClient      *http.Client
	temperature     float64
	maxTokens       int
	transport       string
	reasoningEffort string
}

func NewOpenAIClient(cfg config.Config) *OpenAIClient {
	cfg = cfg.WithLLMProviderDefaults()
	return &OpenAIClient{
		baseURL:         strings.TrimRight(cfg.LLMBaseURL, "/"),
		apiKey:          cfg.LLMAPIKey,
		model:           cfg.LLMModel,
		httpClient:      newHTTPClient(cfg.LLMTimeoutSec),
		temperature:     cfg.LLMTemp,
		maxTokens:       maxTokensOrDefault(cfg.LLMMaxTokens),
		transport:       cfg.LLMTransport,
		reasoningEffort: cfg.LLMReasoningEffort,
	}
}

func (c *OpenAIClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	if c.transport == config.LLMTransportResponses {
		return c.generateResponses(ctx, req)
	}
	return c.generateChatCompletions(ctx, req)
}

func (c *OpenAIClient) generateChatCompletions(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	body := openAIChatRequest{
		Model:       c.model,
		Messages:    buildMessages(req.SystemPrompt, req.Messages),
		Temperature: req.Temperature,
		Stream:      false,
		MaxTokens:   c.maxTokens,
	}
	if body.Temperature == 0.0 {
		body.Temperature = c.temperature
	}
	// Honour the caller's JSONMode. Every LLM-backed agent in this repo sets
	// it (14 call sites) because every one of them parses the reply as a JSON
	// object and fails the stage otherwise. Until now nothing consumed the
	// flag on this path, so "JSON mode" rested entirely on the model choosing
	// to obey the prompt's instructions. Models that narrate before acting —
	// glm-5.2 replies "Let me start by getting the TWE playbook details…" —
	// then break every agent with a parse error.
	if req.JSONMode {
		body.ResponseFormat = &openAIResponseFormat{Type: "json_object"}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("marshal llm request: %w", err)
	}

	// out accumulates the wire bytes as they become known, so every return
	// below carries whatever was already on the wire. The bytes are the
	// point: a reply that parsed cleanly still hides finish_reason and any
	// field the parser does not read.
	out := GenerateResponse{RawRequest: string(payload)}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return out, fmt.Errorf("build llm request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	out.Raw = string(respBody)
	if err != nil {
		return out, fmt.Errorf("read llm response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("llm status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	text, usage, err := parseOpenAIResponse(resp.Header.Get("Content-Type"), respBody)
	if err != nil {
		return out, fmt.Errorf("parse llm response: %w | raw=%s", err, truncateForError(string(respBody), 300))
	}

	out.Text = text
	out.Usage = usage
	return out, nil
}

func (c *OpenAIClient) generateResponses(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	input := make([]map[string]string, 0, len(req.Messages)+1)
	// Keep the system prompt inside input rather than the separate
	// instructions field. Responses JSON mode validates that an input
	// message mentions JSON; several agents put that requirement in their
	// system prompt only, and this is also the wire shape used by the
	// previously successful compatibility proxy.
	if req.SystemPrompt != "" {
		input = append(input, map[string]string{
			"role": "system", "content": req.SystemPrompt,
		})
	}
	for _, message := range req.Messages {
		input = append(input, map[string]string{
			"role": message.Role, "content": message.Content,
		})
	}
	body := openAIResponsesRequest{
		Model:           c.model,
		Input:           input,
		MaxOutputTokens: c.maxTokens,
		Store:           false,
	}
	if c.reasoningEffort != "" {
		body.Reasoning = &openAIReasoning{Effort: c.reasoningEffort}
	} else {
		temperature := req.Temperature
		if temperature == 0 {
			temperature = c.temperature
		}
		body.Temperature = &temperature
	}
	if req.JSONMode {
		body.Text = &openAIResponsesText{Format: openAIResponseFormat{Type: "json_object"}}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("marshal llm request: %w", err)
	}
	out := GenerateResponse{RawRequest: string(payload)}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/responses", bytes.NewReader(payload))
	if err != nil {
		return out, fmt.Errorf("build llm request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	out.Raw = string(respBody)
	if err != nil {
		return out, fmt.Errorf("read llm response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("llm status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	text, usage, err := parseOpenAIResponses(respBody)
	out.Text = text
	out.Usage = usage
	if err != nil {
		return out, fmt.Errorf("parse llm response: %w | raw=%s", err, truncateForError(string(respBody), 300))
	}
	return out, nil
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

type openAIResponsesRequest struct {
	Model           string               `json:"model"`
	Instructions    string               `json:"instructions,omitempty"`
	Input           []map[string]string  `json:"input"`
	Reasoning       *openAIReasoning     `json:"reasoning,omitempty"`
	MaxOutputTokens int                  `json:"max_output_tokens,omitempty"`
	Store           bool                 `json:"store"`
	Text            *openAIResponsesText `json:"text,omitempty"`
	Temperature     *float64             `json:"temperature,omitempty"`
}

type openAIReasoning struct {
	Effort string `json:"effort"`
}

type openAIResponsesText struct {
	Format openAIResponseFormat `json:"format"`
}

type openAIResponsesResponse struct {
	Status            string `json:"status"`
	Error             any    `json:"error"`
	IncompleteDetails struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Output []struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Usage struct {
		InputTokens   int `json:"input_tokens"`
		OutputTokens  int `json:"output_tokens"`
		TotalTokens   int `json:"total_tokens"`
		OutputDetails struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"output_tokens_details"`
	} `json:"usage"`
}

func parseOpenAIResponses(body []byte) (string, Usage, error) {
	var parsed openAIResponsesResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", Usage{}, fmt.Errorf("decode json response: %w", err)
	}
	usage := Usage{
		PromptTokens:     parsed.Usage.InputTokens,
		CompletionTokens: parsed.Usage.OutputTokens,
		TotalTokens:      parsed.Usage.TotalTokens,
	}
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	}
	var parts []string
	for _, output := range parsed.Output {
		for _, content := range output.Content {
			if content.Type == "output_text" && strings.TrimSpace(content.Text) != "" {
				parts = append(parts, content.Text)
			}
		}
	}
	text := strings.Join(parts, "\n")
	if parsed.Status != "" && parsed.Status != "completed" {
		reason := parsed.IncompleteDetails.Reason
		if reason == "" {
			reason = "unspecified"
		}
		if reason == "max_output_tokens" {
			return text, usage, fmt.Errorf("response status=%s reason=%s; raise --llm-max-tokens or TEECHECK_LLM_MAX_TOKENS", parsed.Status, reason)
		}
		return text, usage, fmt.Errorf("response status=%s reason=%s", parsed.Status, reason)
	}
	if parsed.Error != nil {
		return text, usage, fmt.Errorf("response error: %v", parsed.Error)
	}
	if strings.TrimSpace(text) == "" {
		return "", usage, fmt.Errorf("no output_text content found in response")
	}
	return text, usage, nil
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
		// FinishReason distinguishes "the model had nothing to say" from
		// "the model ran out of budget mid-thought". On a reasoning model
		// they look identical from Content alone — glm-5.2 spends the
		// completion budget on reasoning_content first, so exhausting it
		// yields finish_reason "length" with Content empty.
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
		// Reasoning models report how much of the completion budget went to
		// thinking rather than to the answer. Only used to explain a
		// budget-exhaustion failure to the operator.
		CompletionTokensDetails struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}

func parseOpenAIResponse(contentType string, body []byte) (string, Usage, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", Usage{}, fmt.Errorf("empty response body")
	}
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") || strings.HasPrefix(trimmed, "data:") {
		text, err := parseOpenAIStream(trimmed)
		return text, Usage{}, err
	}

	var parsed openAIChatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", Usage{}, fmt.Errorf("decode json response: %w", err)
	}
	text := extractOpenAIText(parsed)
	if strings.TrimSpace(text) == "" {
		// Name the cause. A reasoning model that exhausts max_tokens on its
		// own reasoning returns finish_reason "length" with empty content,
		// which is indistinguishable from "said nothing" unless we look.
		// Reported as "no text content found", it sent one debugging session
		// looking for a parser bug that did not exist.
		if len(parsed.Choices) > 0 && parsed.Choices[0].FinishReason == "length" {
			return "", Usage{}, fmt.Errorf(
				"model exhausted its completion budget before emitting any content "+
					"(finish_reason=length, %d completion tokens of which %d were reasoning); "+
					"raise --llm-max-tokens or TEECHECK_LLM_MAX_TOKENS above the current limit",
				parsed.Usage.CompletionTokens, parsed.Usage.CompletionTokensDetails.ReasoningTokens)
		}
		return "", Usage{}, fmt.Errorf("no text content found in response")
	}
	usage := Usage{
		PromptTokens:     parsed.Usage.PromptTokens,
		CompletionTokens: parsed.Usage.CompletionTokens,
		TotalTokens:      parsed.Usage.TotalTokens,
	}
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	}
	return text, usage, nil
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
