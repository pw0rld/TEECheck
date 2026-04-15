package llm

import "context"

type Message struct {
	Role    string
	Content string
}

type GenerateRequest struct {
	SystemPrompt string
	Messages     []Message
	Temperature  float64
	JSONMode     bool
}

type GenerateResponse struct {
	Text  string
	Raw   string
	Usage Usage
}

// Usage captures token accounting for a single LLM call. Fields are
// zero when the provider did not return usage information — callers
// should treat zero as "unknown", not "free".
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type Client interface {
	Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error)
}
