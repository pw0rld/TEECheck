package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	stream          bool
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
		stream:          cfg.LLMStream,
	}
}

func (c *OpenAIClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	if c.transport == config.LLMTransportResponses {
		if c.stream {
			return GenerateResponse{}, fmt.Errorf("--llm-stream is supported only with chat_completions transport")
		}
		return c.generateResponses(ctx, req)
	}
	return c.generateChatCompletions(ctx, req)
}

func (c *OpenAIClient) generateChatCompletions(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	body := openAIChatRequest{
		Model:     c.model,
		Messages:  buildMessages(req.SystemPrompt, req.Messages),
		Stream:    c.stream,
		MaxTokens: requestOutputLimit(c.maxTokens, req.MaxOutputTokens),
	}
	if c.stream {
		body.StreamOptions = &openAIStreamOptions{IncludeUsage: true}
	}
	// The legacy reasoner rejects/ignores sampling controls. Current DeepSeek
	// thinking models likewise do not use temperature unless thinking is disabled.
	thinking := config.DeepSeekThinkingModel(c.model)
	if config.DeepSeekSupportsThinkingControl(c.model) {
		body.ReasoningEffort = c.reasoningEffort
		if c.reasoningEffort == "none" {
			thinking = false
		}
	}
	if !thinking {
		temperature := req.Temperature
		if temperature == 0.0 {
			temperature = c.temperature
		}
		body.Temperature = &temperature
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
	if c.stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, readErr := io.ReadAll(resp.Body)
		out.Raw = string(respBody)
		if readErr != nil {
			return out, fmt.Errorf("llm status %d: %s; read response: %w", resp.StatusCode, strings.TrimSpace(out.Raw), readErr)
		}
		return out, fmt.Errorf("llm status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	// Consume frames while they arrive, including reasoning-only chunks. Stop
	// at [DONE] rather than waiting for the gateway to close its connection.
	// TeeReader retains the exact bytes consumed, including on partial failures.
	var raw bytes.Buffer
	reader := bufio.NewReader(io.TeeReader(resp.Body, &raw))
	contentType := resp.Header.Get("Content-Type")
	isStream := strings.Contains(strings.ToLower(contentType), "text/event-stream")
	if !isStream && c.stream {
		// Some compatible endpoints omit the SSE content type; others ignore
		// stream:true and return a normal JSON object. Accept both wire formats.
		for {
			first, peekErr := reader.Peek(1)
			if peekErr != nil {
				isStream = true // An empty/interrupted stream is a transport failure.
				break
			}
			if first[0] != ' ' && first[0] != '\t' && first[0] != '\r' && first[0] != '\n' {
				isStream = first[0] != '{' && first[0] != '['
				break
			}
			_, _ = reader.ReadByte()
		}
	}
	var text string
	var usage Usage
	if isStream {
		text, usage, err = parseOpenAIStreamReader(reader)
	} else {
		var respBody []byte
		respBody, err = io.ReadAll(reader)
		if err == nil {
			text, usage, err = parseOpenAIResponse(contentType, respBody)
		} else {
			err = fmt.Errorf("read llm response: %w", err)
		}
	}
	out.Raw, out.Text, out.Usage = raw.String(), text, usage
	if err != nil {
		return out, fmt.Errorf("parse llm response: %w | raw=%s", err, truncateForError(out.Raw, 300))
	}
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
		MaxOutputTokens: requestOutputLimit(c.maxTokens, req.MaxOutputTokens),
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
	Model           string                `json:"model"`
	Messages        []map[string]string   `json:"messages"`
	Temperature     *float64              `json:"temperature,omitempty"`
	ReasoningEffort string                `json:"reasoning_effort,omitempty"`
	Stream          bool                  `json:"stream"`
	StreamOptions   *openAIStreamOptions  `json:"stream_options,omitempty"`
	MaxTokens       int                   `json:"max_tokens,omitempty"`
	ResponseFormat  *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
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
	Usage *openAIChatUsage `json:"usage"`
	Error json.RawMessage  `json:"error"`
}

type openAIChatUsage struct {
	PromptTokens            int `json:"prompt_tokens"`
	CompletionTokens        int `json:"completion_tokens"`
	TotalTokens             int `json:"total_tokens"`
	CompletionTokensDetails struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func (u *openAIChatUsage) accounting() Usage {
	if u == nil {
		return Usage{}
	}
	usage := Usage{PromptTokens: u.PromptTokens, CompletionTokens: u.CompletionTokens, TotalTokens: u.TotalTokens}
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	}
	return usage
}

func completionBudgetError(text string, usage *openAIChatUsage) error {
	completion, reasoning := 0, 0
	if usage != nil {
		completion, reasoning = usage.CompletionTokens, usage.CompletionTokensDetails.ReasoningTokens
	}
	when := "before emitting any content"
	if strings.TrimSpace(text) != "" {
		when = "before completing its content"
	}
	return fmt.Errorf("model exhausted its completion budget %s (finish_reason=length, %d completion tokens of which %d were reasoning); raise --llm-max-tokens or TEECHECK_LLM_MAX_TOKENS above the current limit", when, completion, reasoning)
}

func parseOpenAIResponse(contentType string, body []byte) (string, Usage, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", Usage{}, fmt.Errorf("empty response body")
	}
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") || strings.HasPrefix(trimmed, "data:") {
		return parseOpenAIStream(string(body))
	}
	var parsed openAIChatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", Usage{}, fmt.Errorf("decode json response: %w", err)
	}
	text, usage := extractOpenAIText(parsed), parsed.Usage.accounting()
	if len(parsed.Error) > 0 && string(parsed.Error) != "null" {
		return text, usage, fmt.Errorf("upstream response error: %s", parsed.Error)
	}
	if strings.TrimSpace(text) == "" {
		if len(parsed.Choices) > 0 && parsed.Choices[0].FinishReason == "length" {
			return text, usage, completionBudgetError(text, parsed.Usage)
		}
		return text, usage, fmt.Errorf("no text content found in response")
	}
	return text, usage, nil
}

func parseOpenAIStream(raw string) (string, Usage, error) {
	return parseOpenAIStreamReader(strings.NewReader(raw))
}

// parseOpenAIStreamReader follows SSE event boundaries instead of treating
// each data line as independent JSON. Usage may arrive on its own after the
// finish-reason chunk, so only [DONE] ends a successful Chat Completions stream.
func parseOpenAIStreamReader(reader io.Reader) (string, Usage, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 32<<10), 16<<20)
	scanner.Split(newSSELineSplitter())
	var content, data strings.Builder
	var lastUsage *openAIChatUsage
	finishReason := ""
	eventType := ""
	firstLine := true
	result := func(err error) (string, Usage, error) {
		text, usage := content.String(), lastUsage.accounting()
		if finishReason == "content_filter" {
			return text, usage, fmt.Errorf("upstream policy refusal (finish_reason=content_filter)")
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return text, usage, err
		}
		if finishReason == "length" {
			return text, usage, completionBudgetError(text, lastUsage)
		}
		if err != nil {
			return text, usage, err
		}
		if strings.TrimSpace(text) == "" {
			return text, usage, fmt.Errorf("no text content found in stream response")
		}
		return text, usage, nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			line = strings.TrimPrefix(line, "\ufeff")
			firstLine = false
		}
		if line == "" {
			if data.Len() == 0 {
				eventType = ""
				continue
			}
			payload := strings.TrimSuffix(data.String(), "\n")
			kind := eventType
			eventType = ""
			data.Reset()
			if kind == "error" {
				var chunk openAIChatResponse
				if json.Unmarshal([]byte(payload), &chunk) == nil && chunk.Usage != nil {
					lastUsage = chunk.Usage
				}
				return content.String(), lastUsage.accounting(), fmt.Errorf("upstream stream error: %s", payload)
			}
			if strings.TrimSpace(payload) == "[DONE]" {
				return result(nil)
			}
			var chunk openAIChatResponse
			if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
				return result(fmt.Errorf("decode stream event: %w", err))
			}
			if chunk.Usage != nil {
				lastUsage = chunk.Usage
			}
			if len(chunk.Error) > 0 && string(chunk.Error) != "null" {
				return result(fmt.Errorf("upstream stream error: %s", chunk.Error))
			}
			content.WriteString(extractOpenAIText(chunk))
			for _, choice := range chunk.Choices {
				if choice.FinishReason != "" {
					finishReason = choice.FinishReason
					break
				}
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		} // SSE heartbeat/comment.
		field, value, _ := strings.Cut(line, ":")
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		if field == "data" {
			if data.Len()+len(value)+1 > 16<<20 {
				return result(fmt.Errorf("stream event exceeds 16 MiB"))
			}
			data.WriteString(value)
			data.WriteByte('\n')
		} else if field == "event" {
			eventType = value
		}
	}
	if err := scanner.Err(); err != nil {
		return result(fmt.Errorf("read llm stream: %w", err))
	}
	// An EOF, even after finish_reason, may have dropped the usage trailer or
	// final content. Preserve evidence and let the caller handle the failure.
	return result(fmt.Errorf("stream ended before [DONE]: %w", io.ErrUnexpectedEOF))
}

// Treat CR immediately as a delimiter, then ignore one optional LF. Waiting
// for a following byte would stall a terminal event on an open bare-CR stream.
func newSSELineSplitter() bufio.SplitFunc {
	afterCR := false
	return func(data []byte, atEOF bool) (int, []byte, error) {
		skipped := 0
		if afterCR && len(data) > 0 {
			afterCR = false
			if data[0] == '\n' {
				data = data[1:]
				skipped = 1
			}
		}
		for i, b := range data {
			if b == '\n' {
				return skipped + i + 1, data[:i], nil
			}
			if b == '\r' {
				afterCR = true
				return skipped + i + 1, data[:i], nil
			}
		}
		if atEOF && len(data) > 0 {
			return skipped + len(data), data, nil
		}
		return skipped, nil, nil
	}
}

func extractOpenAIText(resp openAIChatResponse) string {
	for _, choice := range resp.Choices {
		if text := normalizeOpenAIContent(choice.Message.Content); text != "" {
			return text
		}
		if strings.TrimSpace(choice.Text) != "" {
			return choice.Text
		}
		if choice.Delta.Content != "" {
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
