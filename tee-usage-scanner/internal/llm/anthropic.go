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
	// Honour JSONMode. The Messages API has no response_format, so the
	// protocol's own mechanism is used instead: a trailing assistant turn
	// containing just "{" forces the model to continue the object rather
	// than narrate first. Verified against z.ai's /api/anthropic endpoint
	// on 2026-07-28 — glm-5.2 replies `"thought":…}` with no preamble.
	//
	// Without this, "JSON mode" on the GLM path is only a request in the
	// prompt that the model is free to ignore, which is exactly how a live
	// run died on round 1. The OpenAI path was fixed in c54cbfc; that fix
	// did not reach here because NewClient routes the glm preset to this
	// client, and nothing pointed the two implementations at each other.
	if req.JSONMode {
		body.Messages = append(body.Messages, anthropicMessage{Role: "assistant", Content: jsonPrefill})
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

	text, usage, err := parseAnthropicResponse(respBody)
	if err != nil {
		return GenerateResponse{}, fmt.Errorf("parse anthropic response: %w | raw=%s", err, truncateForError(string(respBody), 300))
	}

	if req.JSONMode {
		text = restorePrefill(text)
	}

	return GenerateResponse{
		Text:  text,
		Raw:   string(respBody),
		Usage: usage,
	}, nil
}

// jsonPrefill is the assistant turn that opens the object the model must
// complete. It carries no trailing whitespace: the Messages API rejects a
// prefill that ends in whitespace.
const jsonPrefill = "{"

// restorePrefill puts back the brace the prefilled turn opened, because a
// prefilled turn is not echoed back — the reply is the continuation only.
//
// It does NOT do so blindly. Prefill is honoured intermittently, exactly as
// response_format is on the OpenAI path: observed against glm-5.2 on
// 2026-07-28, one reply continued the object correctly while another ignored
// the prefill and opened a fresh ```json fence. Prepending a brace to that
// second shape would turn a reply the extractor can recover into one it
// cannot — the fix would manufacture a new defect on the very path it exists
// to protect. So when the continuation already opens an object or a fence,
// the model restarted and the reply is returned untouched.
func restorePrefill(text string) string {
	trimmed := strings.TrimLeft(text, " \t\r\n")
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "```") {
		return text
	}
	return jsonPrefill + text
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
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
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

func parseAnthropicResponse(body []byte) (string, Usage, error) {
	var parsed anthropicMessagesResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", Usage{}, fmt.Errorf("decode json response: %w", err)
	}

	var parts []string
	for _, block := range parsed.Content {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			parts = append(parts, block.Text)
		}
	}
	if len(parts) == 0 {
		return "", Usage{}, fmt.Errorf("no text content found in response")
	}
	usage := Usage{
		PromptTokens:     parsed.Usage.InputTokens,
		CompletionTokens: parsed.Usage.OutputTokens,
		TotalTokens:      parsed.Usage.InputTokens + parsed.Usage.OutputTokens,
	}
	return strings.Join(parts, ""), usage, nil
}
