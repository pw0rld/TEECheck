package llm_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// fakeClient is a test double implementing llm.Client with scripted
// responses. Each call pops one entry from responses.
type fakeClient struct {
	responses []fakeResponse
	calls     atomic.Int32
}

type fakeResponse struct {
	text string
	err  error
}

func (f *fakeClient) Generate(_ context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
	i := f.calls.Add(1) - 1
	if int(i) >= len(f.responses) {
		return llm.GenerateResponse{}, fmt.Errorf("fakeClient: out of scripted responses (call %d)", i+1)
	}
	r := f.responses[i]
	return llm.GenerateResponse{Text: r.text}, r.err
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context canceled", context.Canceled, false},
		{"context deadline", context.DeadlineExceeded, true},
		{"anthropic 500", fmt.Errorf("anthropic status 500: internal error"), true},
		{"anthropic 503", fmt.Errorf("openai status 503: service unavailable"), true},
		{"anthropic 401", fmt.Errorf("anthropic status 401: unauthorized"), false},
		{"anthropic 400", fmt.Errorf("anthropic status 400: bad request"), false},
		{"connection reset", errors.New("connection reset by peer"), true},
		{"connection refused", errors.New("connection refused"), true},
		{"i/o timeout wrapped", fmt.Errorf("Post https://...: i/o timeout"), true},
		{"Client.Timeout", errors.New("Client.Timeout exceeded while awaiting headers"), true},
		{"invalid json", errors.New("parse llm response: invalid character"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := llm.IsTransient(tt.err); got != tt.want {
				t.Errorf("IsTransient(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryingClient_SuccessOnFirstAttempt(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{{text: "ok"}}}
	client := llm.NewRetryingClient(fake, llm.RetryConfig{BaseDelay: time.Millisecond})

	resp, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "ok" {
		t.Errorf("Text = %q, want 'ok'", resp.Text)
	}
	if fake.calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", fake.calls.Load())
	}
}

func TestRetryingClient_RetriesOn5xxThenSucceeds(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{
		{err: fmt.Errorf("anthropic status 500: internal error")},
		{err: fmt.Errorf("anthropic status 503: unavailable")},
		{text: "finally ok"},
	}}
	client := llm.NewRetryingClient(fake, llm.RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond * 10,
	})

	resp, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "finally ok" {
		t.Errorf("Text = %q, want 'finally ok'", resp.Text)
	}
	if fake.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", fake.calls.Load())
	}
}

func TestRetryingClient_DoesNotRetryOn4xx(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{
		{err: fmt.Errorf("anthropic status 401: unauthorized")},
	}}
	client := llm.NewRetryingClient(fake, llm.RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
	})

	_, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if fake.calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (non-transient, no retry)", fake.calls.Load())
	}
}

func TestRetryingClient_ExhaustsAllAttempts(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{
		{err: fmt.Errorf("connection reset by peer")},
		{err: fmt.Errorf("connection reset by peer")},
		{err: fmt.Errorf("connection reset by peer")},
	}}
	client := llm.NewRetryingClient(fake, llm.RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond * 10,
	})

	_, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if err == nil {
		t.Fatal("expected error after exhaustion")
	}
	if fake.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", fake.calls.Load())
	}
}

func TestRetryingClient_HonorsContextCancel(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{
		{err: fmt.Errorf("anthropic status 500: internal")},
		{err: fmt.Errorf("anthropic status 500: internal")},
		{text: "ok"},
	}}
	client := llm.NewRetryingClient(fake, llm.RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   50 * time.Millisecond, // long enough for cancel to land
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err := client.Generate(ctx, llm.GenerateRequest{})
	if err == nil {
		t.Fatal("expected error from canceled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

func TestRetryingClient_LoggerCalledOnRetry(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{
		{err: fmt.Errorf("anthropic status 500: err")},
		{text: "ok"},
	}}
	var loggedAttempts []int
	client := llm.NewRetryingClient(fake, llm.RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
		Logger: func(attempt int, err error, wait time.Duration) {
			loggedAttempts = append(loggedAttempts, attempt)
		},
	})

	if _, err := client.Generate(context.Background(), llm.GenerateRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(loggedAttempts) != 1 || loggedAttempts[0] != 1 {
		t.Errorf("loggedAttempts = %v, want [1]", loggedAttempts)
	}
}
