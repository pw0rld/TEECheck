package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RetryConfig controls the behavior of NewRetryingClient.
type RetryConfig struct {
	// MaxAttempts is the total number of attempts including the first
	// one. Must be >= 1. Defaults to 3 if zero.
	MaxAttempts int
	// BaseDelay is the initial backoff duration before the first retry.
	// Defaults to 5 seconds if zero.
	BaseDelay time.Duration
	// MaxDelay caps a single backoff wait. Defaults to 90 seconds if zero.
	MaxDelay time.Duration
	// Logger, if non-nil, is called once per retry attempt AFTER a
	// transient error is observed and BEFORE the backoff wait. It
	// receives the attempt number that just failed (1-indexed), the
	// error, and the planned wait duration. Use this for telemetry
	// or to stream retry progress to stdout.
	Logger func(failedAttempt int, err error, waitBeforeNext time.Duration)
}

// NewRetryingClient wraps an underlying llm.Client with retry-on-
// transient-error semantics. Non-transient errors (4xx, parse errors,
// context cancellation) short-circuit immediately. Transient errors
// (5xx, connection resets, i/o timeouts, request deadline exceeded)
// retry with exponential backoff capped at MaxDelay.
//
// This is the defense against GLM's intermittent 5xx responses and
// network hiccups observed in v3 and v11 dogfood runs, where a single
// transient failure killed the entire 8-round audit.
func NewRetryingClient(inner Client, cfg RetryConfig) Client {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 5 * time.Second
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 90 * time.Second
	}
	return &retryingClient{inner: inner, cfg: cfg}
}

type retryingClient struct {
	inner Client
	cfg   RetryConfig
}

func (r *retryingClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	// Refuse an impossible request before the first attempt, not after the
	// third. An oversized prompt fails as a timeout waiting for response
	// headers, which IsTransient cannot tell from a network fault — so it
	// gets retried, at full timeout each time, and the record blames the
	// provider. See MaxRequestBytes.
	if err := checkRequestSize(req); err != nil {
		return GenerateResponse{}, err
	}
	var lastErr error
	for attempt := 1; attempt <= r.cfg.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return GenerateResponse{}, ctx.Err()
		}
		resp, err := r.inner.Generate(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !IsTransient(err) {
			return GenerateResponse{}, err
		}
		if attempt == r.cfg.MaxAttempts {
			break
		}
		wait := backoff(r.cfg.BaseDelay, r.cfg.MaxDelay, attempt)
		if r.cfg.Logger != nil {
			r.cfg.Logger(attempt, err, wait)
		}
		select {
		case <-ctx.Done():
			return GenerateResponse{}, ctx.Err()
		case <-time.After(wait):
		}
	}
	return GenerateResponse{}, fmt.Errorf("llm retry exhausted after %d attempts: %w", r.cfg.MaxAttempts, lastErr)
}

// backoff returns the wait duration for the given attempt number
// (1-indexed). attempt=1 returns base; attempt=2 returns 3*base;
// attempt=3 returns 9*base; and so on, capped at max.
func backoff(base, max time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt; i++ {
		d *= 3
		if d > max {
			return max
		}
	}
	return d
}

// IsTransient reports whether an error from an LLM Generate call is
// likely to succeed on retry. The set of retryable errors is:
//
//   - HTTP 5xx status codes (server error, bad gateway, unavailable,
//     gateway timeout, etc.)
//   - Network-level connection resets, refusals, timeouts
//   - i/o timeouts including Go's "Client.Timeout" text
//   - context.DeadlineExceeded on an individual request (but NOT
//     context.Canceled, which signals a caller-initiated stop)
//
// Not retryable:
//   - HTTP 4xx status codes (auth, validation, quota)
//   - JSON parse failures (nondeterministic prompt issue, not network)
//   - context.Canceled (user requested stop)
//   - Any other error
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	// Explicit HTTP 5xx.
	if strings.Contains(msg, "status 500") || strings.Contains(msg, "status 501") ||
		strings.Contains(msg, "status 502") || strings.Contains(msg, "status 503") ||
		strings.Contains(msg, "status 504") || strings.Contains(msg, "status 505") ||
		strings.Contains(msg, "status 506") || strings.Contains(msg, "status 507") ||
		strings.Contains(msg, "status 508") || strings.Contains(msg, "status 509") ||
		strings.Contains(msg, "status 510") || strings.Contains(msg, "status 511") {
		return true
	}
	// Network-level symptoms.
	if strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "eof") ||
		strings.Contains(msg, "client.timeout") {
		return true
	}
	return false
}
