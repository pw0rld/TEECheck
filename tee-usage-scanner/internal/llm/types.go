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

// GenerateResponse carries both what the caller needs and what a debugger
// needs.
//
// Text is the extracted assistant message. RawRequest and Raw are the exact
// bytes on the wire, in both directions, and they exist because Text alone
// cannot answer the questions that come up when a reply is wrong: was
// response_format actually sent, what was finish_reason, did the provider
// return a reasoning field the extractor ignored, did it warn about
// anything. On 2026-08-04 a planner run died on two consecutive non-JSON
// replies and none of those questions could be answered from the artifacts,
// because the raw body was read, parsed and dropped.
//
// They are populated on the error paths too, wherever the bytes exist. A
// call that failed is the one someone will be diagnosing.
type GenerateResponse struct {
	Text string
	// RawRequest is the exact body POSTed to the provider. The API key
	// travels in a header, not here, so this is safe to persist.
	RawRequest string
	// Raw is the exact body the provider returned, before parsing.
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
