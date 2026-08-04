package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// countingClient records how many times it was asked to generate.
type countingClient struct {
	calls int
	err   error
}

func (c *countingClient) Generate(context.Context, GenerateRequest) (GenerateResponse, error) {
	c.calls++
	return GenerateResponse{Text: "ok"}, c.err
}

func oversizedRequest() GenerateRequest {
	return GenerateRequest{
		SystemPrompt: "You are the Verifier Agent.",
		Messages: []Message{
			{Role: "user", Content: "Case inv-state-001"},
			{Role: "assistant", Content: "status: contested"},
			{Role: "user", Content: strings.Repeat("a", MaxRequestBytes+1)},
		},
	}
}

// A request that cannot succeed must not be attempted, let alone retried.
//
// On 2026-08-02 an 82 MB verifier prompt surfaced as "context deadline
// exceeded while awaiting headers" — indistinguishable from a network fault.
// It was retried three times at ten minutes each: thirty minutes spent, the
// run lost, and two separate investigations blamed the provider.
func TestRetryingClient_RefusesAnOversizedRequestWithoutSending(t *testing.T) {
	inner := &countingClient{}
	c := NewRetryingClient(inner, RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond})

	_, err := c.Generate(context.Background(), oversizedRequest())
	if err == nil {
		t.Fatal("an oversized request must be refused")
	}
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("error must be identifiable as too-large, got: %v", err)
	}
	if inner.calls != 0 {
		t.Errorf("the request must never be sent; inner was called %d time(s)", inner.calls)
	}
}

// The error has to say which part grew. "Too large" alone sends the reader
// back to guess among a system prompt, a case pack and three bus answers.
func TestCheckRequestSize_NamesTheLargestPart(t *testing.T) {
	err := checkRequestSize(oversizedRequest())
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"message 3/3", `role "user"`, "unbounded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must point at the offending input (%q):\n%v", want, err)
		}
	}
}

// Too-large must not be transient. Retrying reproduces the same failure at
// the same cost — which is exactly what happened, twice.
func TestErrRequestTooLarge_IsNotTransient(t *testing.T) {
	if IsTransient(checkRequestSize(oversizedRequest())) {
		t.Fatal("an oversized request must not be classified transient")
	}
}

// Ordinary requests pass through untouched. The guardrail sits far above any
// prompt that could succeed, so it must never be the reason a run fails.
func TestRetryingClient_NormalRequestIsUnaffected(t *testing.T) {
	inner := &countingClient{}
	c := NewRetryingClient(inner, RetryConfig{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond})

	if _, err := c.Generate(context.Background(), GenerateRequest{
		SystemPrompt: "You are the Verifier Agent.",
		Messages:     []Message{{Role: "user", Content: strings.Repeat("b", 200_000)}},
	}); err != nil {
		t.Fatalf("a 200 KB request must go through: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("inner calls = %d, want 1", inner.calls)
	}
}
