package llm_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	text  string
	err   error
	raw   string
	usage llm.Usage
}

func (f *fakeClient) Generate(_ context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
	i := f.calls.Add(1) - 1
	if int(i) >= len(f.responses) {
		return llm.GenerateResponse{}, fmt.Errorf("fakeClient: out of scripted responses (call %d)", i+1)
	}
	r := f.responses[i]
	return llm.GenerateResponse{Text: r.text, Raw: r.raw, Usage: r.usage}, r.err
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
		{"ordinary 502", fmt.Errorf("openai status 502: bad gateway"), true},
		{"anthropic 503", fmt.Errorf("openai status 503: service unavailable"), true},
		{"gateway timeout", fmt.Errorf("openai status 504: gateway timeout"), true},
		{"rate limited", errors.New("llm status 429: too many requests"), true},
		{"http rate limited", errors.New("HTTP 429: try again later"), true},
		{"structured rate limited", errors.New(`{"error":{"type":"rate_limit_error"}}`), true},
		{"anthropic 401", fmt.Errorf("anthropic status 401: unauthorized"), false},
		{"anthropic 400", fmt.Errorf("anthropic status 400: bad request"), false},
		{"forbidden with rate limit text", errors.New("llm status 403: rate_limit_error"), false},
		{"not found with timeout text", errors.New("llm status 404: i/o timeout"), false},
		{"validation wins over wrapped deadline", errors.Join(errors.New("llm status 400: bad request"), context.DeadlineExceeded), false},
		{"policy wins over rate limit", errors.New("llm status 429: rate_limit_error; content_filter"), false},
		{"canceled rate limit", errors.Join(errors.New("llm status 429: rate limited"), context.Canceled), false},
		{"invalid status prefix", errors.New("llm status 4290: unknown code"), false},
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

func TestIsPolicyRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"cybersecurity refusal", errors.New("HTTP 502: flagged for possible cybersecurity risk"), true},
		{"case insensitive", errors.New("HTTP 502: FLAGGED FOR POSSIBLE CYBERSECURITY RISK"), true},
		{"whitespace separated", errors.New("status 502: flagged for possible\ncybersecurity risk"), true},
		{"wrapped safeguards refusal", fmt.Errorf("generate: %w", errors.New("cyber permissive safeguards")), true},
		{"structured filter code", errors.New(`status 400: {"code":"content_filter"}`), true},
		{"content policy", errors.New("status 502: content policy violation"), true},
		{"structured policy code", errors.New(`status 400: {"code":"content_policy_violation"}`), true},
		{"ordinary gateway", errors.New("openai status 502: bad gateway"), false},
		{"ordinary timeout", context.DeadlineExceeded, false},
		{"unrelated policy", errors.New("status 502: database retention policy unavailable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := llm.IsPolicyRefusal(tc.err); got != tc.want {
				t.Fatalf("IsPolicyRefusal(%v)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

type refusalClient struct {
	response llm.GenerateResponse
	err      error
	requests []llm.GenerateRequest
}

func (c *refusalClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.requests = append(c.requests, req)
	return c.response, c.err
}

func TestIsTransient_PolicyRefusalShortCircuits(t *testing.T) {
	refusal := errors.New("openai status 502: flagged for possible cybersecurity risk")
	if llm.IsTransient(refusal) {
		t.Fatal("a policy refusal must not be retried as a gateway failure")
	}
	// A transport wrapper must not override an explicit policy decision.
	if llm.IsTransient(errors.Join(context.DeadlineExceeded, refusal)) {
		t.Fatal("wrapped policy refusal must take precedence over timeout classification")
	}
	inner := &refusalClient{
		err: refusal,
		response: llm.GenerateResponse{
			RawRequest: `{"model":"test-model","input":"original request"}`,
			Raw:        `{"error":"flagged for possible cybersecurity risk"}`,
			Usage:      llm.Usage{PromptTokens: 7, TotalTokens: 7},
		},
	}
	logged := 0
	client := llm.NewRetryingClient(inner, llm.RetryConfig{
		BaseDelay: time.Millisecond,
		Logger:    func(int, error, time.Duration) { logged++ },
	})
	req := llm.GenerateRequest{
		SystemPrompt: "Original defensive review request",
		Messages:     []llm.Message{{Role: "user", Content: "Original source evidence"}},
		JSONMode:     true,
	}
	resp, err := client.Generate(context.Background(), req)
	if !errors.Is(err, refusal) {
		t.Fatalf("refusal was not preserved: %v", err)
	}
	if len(inner.requests) != 1 || logged != 0 {
		t.Fatalf("requests=%d retry logs=%d; want one unchanged request and no retries", len(inner.requests), logged)
	}
	if !reflect.DeepEqual(inner.requests[0], req) {
		t.Fatal("retry wrapper changed the rejected request")
	}
	if !reflect.DeepEqual(resp, inner.response) {
		t.Fatalf("refusal wire evidence was discarded: got %+v, want %+v", resp, inner.response)
	}
}

func TestRetryingClient_PreservesLastErrorResponse(t *testing.T) {
	upstreamErr := errors.New("openai status 502: temporary gateway failure")
	inner := &refusalClient{
		err: upstreamErr,
		response: llm.GenerateResponse{
			RawRequest: `{"model":"test-model"}`,
			Raw:        `{"error":"temporary gateway failure"}`,
		},
	}
	client := llm.NewRetryingClient(inner, llm.RetryConfig{
		MaxAttempts: 2,
		BaseDelay:   time.Millisecond,
	})
	resp, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if len(inner.requests) != 2 || !errors.Is(err, upstreamErr) {
		t.Fatalf("ordinary transient behavior changed: calls=%d err=%v", len(inner.requests), err)
	}
	if !reflect.DeepEqual(resp, inner.response) {
		t.Fatalf("last failure response was discarded: %+v", resp)
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

func TestRetryingClient_RateLimitBackoffThenSuccess(t *testing.T) {
	fake := &fakeClient{responses: []fakeResponse{
		{err: errors.New("llm status 429: too many requests")},
		{err: errors.New(`{"error":{"type":"rate_limit_error"}}`)},
		{text: "completed after rate limit"},
	}}
	var delays []time.Duration
	client := llm.NewRetryingClient(fake, llm.RetryConfig{
		MaxAttempts: 3,
		BaseDelay:   time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Logger: func(attempt int, _ error, delay time.Duration) {
			if attempt != len(delays)+1 {
				t.Errorf("retry attempt=%d, want %d", attempt, len(delays)+1)
			}
			delays = append(delays, delay)
		},
	})
	resp, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if err != nil || resp.Text != "completed after rate limit" || fake.calls.Load() != 3 {
		t.Fatalf("response=%+v err=%v calls=%d", resp, err, fake.calls.Load())
	}
	for i, want := range []time.Duration{time.Millisecond, 3 * time.Millisecond} {
		if delays[i] < want-want/10 || delays[i] > want {
			t.Fatalf("jittered delay[%d]=%v, want [%v,%v]", i, delays[i], want-want/10, want)
		}
	}
}

func TestRetryingClient_DefaultFiveAttempts(t *testing.T) {
	for _, status := range []int{429, 502, 503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			failure := fmt.Errorf("llm status %d: temporary failure", status)
			inner := &refusalClient{err: failure, response: llm.GenerateResponse{Usage: llm.Usage{PromptTokens: 2, CompletionTokens: 1, TotalTokens: 3}}}
			var attempts []int
			client := llm.NewRetryingClient(inner, llm.RetryConfig{
				BaseDelay: time.Nanosecond,
				MaxDelay:  time.Nanosecond,
				Logger:    func(attempt int, _ error, _ time.Duration) { attempts = append(attempts, attempt) },
			})
			resp, err := client.Generate(context.Background(), llm.GenerateRequest{})
			if !errors.Is(err, failure) || len(inner.requests) != 5 || !reflect.DeepEqual(attempts, []int{1, 2, 3, 4}) || resp.Usage != (llm.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15}) {
				t.Fatalf("err=%v calls=%d attempts=%v usage=%+v", err, len(inner.requests), attempts, resp.Usage)
			}
		})
	}
}

func TestRetryingClient_JitterStaysWithinCap(t *testing.T) {
	const base = 100 * time.Microsecond
	const max = 500 * time.Microsecond
	inner := &refusalClient{err: errors.New("llm status 503: unavailable")}
	var delays []time.Duration
	client := llm.NewRetryingClient(inner, llm.RetryConfig{
		BaseDelay: base, MaxDelay: max,
		Logger: func(_ int, _ error, delay time.Duration) { delays = append(delays, delay) },
	})
	_, _ = client.Generate(context.Background(), llm.GenerateRequest{})
	if len(delays) != 4 {
		t.Fatalf("delays=%v", delays)
	}
	for i, cap := range []time.Duration{base, 3 * base, max, max} {
		if delays[i] < cap-cap/10 || delays[i] > cap {
			t.Fatalf("delay[%d]=%v outside [%v,%v]", i, delays[i], cap-cap/10, cap)
		}
	}
}

func TestRetryingClient_BaseDelayAlsoHonorsCap(t *testing.T) {
	inner := &refusalClient{err: errors.New("llm status 503: unavailable")}
	var delay time.Duration
	client := llm.NewRetryingClient(inner, llm.RetryConfig{
		MaxAttempts: 2, BaseDelay: time.Hour, MaxDelay: time.Microsecond,
		Logger: func(_ int, _ error, d time.Duration) { delay = d },
	})
	_, _ = client.Generate(context.Background(), llm.GenerateRequest{})
	if delay < 900*time.Nanosecond || delay > time.Microsecond {
		t.Fatalf("initial delay exceeded cap: %v", delay)
	}
}

func TestRetryingClient_CancelStopsBeforeSecondAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := &refusalClient{err: errors.New("llm status 504: gateway timeout")}
	client := llm.NewRetryingClient(inner, llm.RetryConfig{
		BaseDelay: time.Hour,
		Logger:    func(_ int, _ error, _ time.Duration) { cancel() },
	})
	_, err := client.Generate(ctx, llm.GenerateRequest{})
	if !errors.Is(err, context.Canceled) || len(inner.requests) != 1 {
		t.Fatalf("err=%v calls=%d", err, len(inner.requests))
	}
}

func TestRetryingClient_AccumulatesKnownUsageAcrossAttempts(t *testing.T) {
	inner := &fakeClient{responses: []fakeResponse{
		{err: errors.New("read stream: unexpected EOF"), raw: "failed stream", usage: llm.Usage{PromptTokens: 10, CompletionTokens: 4, TotalTokens: 14}},
		{text: "complete", raw: "successful stream", usage: llm.Usage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18}},
	}}
	client := llm.NewRetryingClient(inner, llm.RetryConfig{BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond})
	resp, err := client.Generate(context.Background(), llm.GenerateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	want := llm.Usage{PromptTokens: 21, CompletionTokens: 11, TotalTokens: 32}
	if resp.Usage != want || resp.Text != "complete" || resp.Raw != "successful stream" {
		t.Fatalf("response=%+v", resp)
	}
}

func TestRetryingClient_PreservesKnownUsageOnErrorAndCancel(t *testing.T) {
	for _, cancelDuringBackoff := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelDuringBackoff), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inner := &fakeClient{responses: []fakeResponse{
				{err: errors.New("read stream: unexpected EOF"), usage: llm.Usage{PromptTokens: 10, CompletionTokens: 4}},
				{err: errors.New("llm status 400: bad request"), usage: llm.Usage{PromptTokens: 3, TotalTokens: 3}},
			}}
			cfg := llm.RetryConfig{BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond}
			if cancelDuringBackoff {
				cfg.Logger = func(int, error, time.Duration) { cancel() }
			}
			resp, err := llm.NewRetryingClient(inner, cfg).Generate(ctx, llm.GenerateRequest{})
			want := llm.Usage{PromptTokens: 13, CompletionTokens: 4, TotalTokens: 17}
			if cancelDuringBackoff {
				want = llm.Usage{PromptTokens: 10, CompletionTokens: 4, TotalTokens: 14}
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			if err == nil || resp.Usage != want {
				t.Fatalf("response=%+v err=%v", resp, err)
			}
		})
	}
}

func TestRetryingClient_DoesNotRetryOn4xx(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			failure := fmt.Errorf("anthropic status %d: request rejected", status)
			fake := &fakeClient{responses: []fakeResponse{{err: failure}}}
			client := llm.NewRetryingClient(fake, llm.RetryConfig{
				MaxAttempts: 3,
				BaseDelay:   time.Millisecond,
			})
			_, err := client.Generate(context.Background(), llm.GenerateRequest{})
			if !errors.Is(err, failure) || fake.calls.Load() != 1 {
				t.Fatalf("err=%v calls=%d, want original error after one call", err, fake.calls.Load())
			}
		})
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
