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
	Text string
	Raw  string
}

type Client interface {
	Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error)
}
