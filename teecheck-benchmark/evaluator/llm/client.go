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
)

type Client struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

func (c Client) Complete(ctx context.Context, prompt string) (string, error) {
	if c.BaseURL == "" || c.APIKey == "" || c.Model == "" {
		return "", fmt.Errorf("llm client requires base URL, API key, and model")
	}
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 5 * time.Minute}
	}
	body, err := json.Marshal(chatRequest{Model: c.Model, Temperature: 0, Messages: []chatMessage{{Role: "system", Content: "You are a security benchmark judge. Return JSON only."}, {Role: "user", Content: prompt}}})
	if err != nil {
		return "", err
	}
	// Retry transient failures (network errors, 429, 5xx) with backoff, like
	// the scanner-side client. A single bad response must not abort a batch.
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		out, retryable, err := c.once(ctx, h, body)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryable {
			return "", err
		}
	}
	return "", fmt.Errorf("llm request failed after retries: %w", lastErr)
}

// once performs a single request. It returns retryable=true for transient
// conditions (network error, HTTP 429/5xx) so the caller can back off.
func (c Client) once(ctx context.Context, h *http.Client, body []byte) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		return "", true, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode/100 == 5
		return "", retryable, fmt.Errorf("llm HTTP %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var out chatResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return "", false, err
	}
	if len(out.Choices) == 0 {
		return "", false, fmt.Errorf("llm response contains no choices")
	}
	return out.Choices[0].Message.Content, false, nil
}
