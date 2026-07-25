// Package llmtest provides test doubles for internal/llm. It is imported
// only from *_test.go files and never linked into a production binary.
package llmtest

import (
	"context"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// FakeClient is a deterministic llm.Client for tests. It returns the queued
// Responses in order (as GenerateResponse.Text and .Raw); once exhausted it
// returns Default. If Err is set, Generate returns it. Every request is
// recorded in Calls for assertions.
type FakeClient struct {
	Responses []string
	Default   string
	Err       error
	Calls     []llm.GenerateRequest
	idx       int
}

func (f *FakeClient) Generate(ctx context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	f.Calls = append(f.Calls, req)
	if f.Err != nil {
		return llm.GenerateResponse{}, f.Err
	}
	content := f.Default
	if f.idx < len(f.Responses) {
		content = f.Responses[f.idx]
		f.idx++
	}
	return llm.GenerateResponse{Text: content, Raw: content}, nil
}
