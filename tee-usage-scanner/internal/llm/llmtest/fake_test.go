package llmtest

import (
	"context"
	"errors"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func TestFakeClient_ReturnsQueuedThenDefault(t *testing.T) {
	f := &FakeClient{Responses: []string{"first", "second"}, Default: "fallback"}
	got1, _ := f.Generate(context.Background(), llm.GenerateRequest{})
	got2, _ := f.Generate(context.Background(), llm.GenerateRequest{})
	got3, _ := f.Generate(context.Background(), llm.GenerateRequest{})
	if got1.Text != "first" || got2.Text != "second" || got3.Text != "fallback" {
		t.Fatalf("got %q,%q,%q", got1.Text, got2.Text, got3.Text)
	}
	if got1.Raw != "first" {
		t.Errorf("Raw should mirror Text, got %q", got1.Raw)
	}
	if len(f.Calls) != 3 {
		t.Errorf("expected 3 recorded calls, got %d", len(f.Calls))
	}
}

func TestFakeClient_ReturnsErr(t *testing.T) {
	sentinel := errors.New("boom")
	f := &FakeClient{Err: sentinel}
	if _, err := f.Generate(context.Background(), llm.GenerateRequest{}); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}
