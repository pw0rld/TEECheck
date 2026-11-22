package llm

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultRetryAttempts = 5

// RetryConfig controls the behavior of NewRetryingClient.
type RetryConfig struct {
	// MaxAttempts is the total number of attempts including the first
	// one. Must be >= 1. Defaults to 5 if zero.
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
// transient-error semantics. Non-transient errors (4xx except 429, policy refusals,
// parse errors, context cancellation) short-circuit immediately. Transient errors
// (429, rate limiting, 5xx, connection resets, i/o timeouts, request deadline exceeded)
// retry with exponential backoff, 0–10% downward jitter, and a MaxDelay cap.
//
// This is the defense against GLM's intermittent 5xx responses and
// network hiccups observed in v3 and v11 dogfood runs, where a single
// transient failure killed the entire 8-round audit.
func NewRetryingClient(inner Client, cfg RetryConfig) Client {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultRetryAttempts
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
	// fifth. An oversized prompt fails as a timeout waiting for response
	// headers, which IsTransient cannot tell from a network fault — so it
	// gets retried, at full timeout each time, and the record blames the
	// provider. See MaxRequestBytes.
	if err := checkRequestSize(req); err != nil {
		return GenerateResponse{}, err
	}
	var lastErr error
	var lastResponse GenerateResponse
	var knownUsage Usage
	for attempt := 1; attempt <= r.cfg.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return lastResponse, ctx.Err()
		}
		resp, err := r.inner.Generate(ctx, req)
		// Failed streams can still carry a final usage chunk. Keep all known
		// attempt costs while retaining the last attempt's wire evidence.
		knownUsage = addKnownUsage(knownUsage, resp.Usage)
		resp.Usage = knownUsage
		if err == nil {
			return resp, nil
		}
		lastErr = err
		lastResponse = resp
		if !IsTransient(err) {
			return resp, err
		}
		if attempt == r.cfg.MaxAttempts {
			break
		}
		wait := retryDelay(r.cfg.BaseDelay, r.cfg.MaxDelay, attempt)
		if r.cfg.Logger != nil {
			r.cfg.Logger(attempt, err, wait)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastResponse, ctx.Err()
		case <-timer.C:
		}
	}
	return lastResponse, fmt.Errorf("llm retry exhausted after %d attempts: %w", r.cfg.MaxAttempts, lastErr)
}

func addKnownUsage(total, usage Usage) Usage {
	if usage.PromptTokens > 0 {
		total.PromptTokens += usage.PromptTokens
	}
	if usage.CompletionTokens > 0 {
		total.CompletionTokens += usage.CompletionTokens
	}
	if usage.TotalTokens > 0 {
		total.TotalTokens += usage.TotalTokens
	} else {
		// Derive a missing total only from measured component counts, never
		// estimate the unreported cost of a failed attempt.
		if usage.PromptTokens > 0 {
			total.TotalTokens += usage.PromptTokens
		}
		if usage.CompletionTokens > 0 {
			total.TotalTokens += usage.CompletionTokens
		}
	}
	return total
}

// backoff returns the wait duration for the given attempt number
// (1-indexed). attempt=1 returns base; attempt=2 returns 3*base;
// attempt=3 returns 9*base; and so on, capped at max.
func backoff(base, max time.Duration, attempt int) time.Duration {
	if base >= max {
		return max
	}
	d := base
	for i := 1; i < attempt; i++ {
		// Compare before multiplying to avoid duration overflow.
		if d > max/3 {
			return max
		}
		d *= 3
	}
	return d
}

// Small downward jitter spreads synchronized retries without exceeding either
// the configured cap or the existing exponential schedule. Nanosecond delays
// used by tests remain valid when the jitter window rounds down to zero.
func retryDelay(base, max time.Duration, attempt int) time.Duration {
	delay := backoff(base, max, attempt)
	window := delay / 10
	if window <= 0 {
		return delay
	}
	return delay - time.Duration(rand.Int64N(int64(window)+1))
}

// IsPolicyRefusal identifies explicit upstream content/safety policy refusal
// markers, including providers that incorrectly wrap a refusal in HTTP 5xx.
// It classifies the response for reporting and retry control; it never changes
// the request or attempts to work around the upstream decision.
func IsPolicyRefusal(err error) bool {
	if err == nil {
		return false
	}
	message := strings.Join(strings.Fields(strings.ToLower(err.Error())), " ")
	for _, marker := range []string{
		"flagged for possible cybersecurity risk",
		"cyber permissive safeguards",
		"content_filter",
		"content policy violation",
		"content_policy_violation",
		"responsibleaipolicyviolation",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

// IsTransient reports whether an error from an LLM Generate call is
// likely to succeed on retry. The set of retryable errors is:
//
//   - HTTP 429 / rate_limit_error responses
//   - HTTP 5xx status codes (server error, bad gateway, unavailable,
//     gateway timeout, etc.)
//   - Network-level connection resets, refusals, timeouts
//   - i/o timeouts including Go's "Client.Timeout" text
//   - context.DeadlineExceeded on an individual request (but NOT
//     context.Canceled, which signals a caller-initiated stop)
//
// Not retryable:
//   - Explicit content/safety policy refusals, even with HTTP 5xx status
//   - Other HTTP 4xx status codes (auth, validation)
//   - JSON parse failures (nondeterministic prompt issue, not network)
//   - context.Canceled (user requested stop)
//   - Any other error
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if IsPolicyRefusal(err) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	msg := strings.ToLower(err.Error())
	// An explicit HTTP response takes precedence over incidental transport
	// words in its body. In particular, an auth/validation failure mentioning
	// "timeout" or "rate_limit_error" must not become retryable.
	if match := responseStatus.FindStringSubmatch(msg); len(match) == 2 {
		status, _ := strconv.Atoi(match[1])
		if status >= 400 && status < 500 {
			return status == 429
		}
		if status >= 500 && status < 600 {
			return true
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if strings.Contains(msg, "rate_limit_error") {
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

var responseStatus = regexp.MustCompile(`\b(?:status(?: code)?|http)(?:\s*:\s*|\s+)([0-9]{3})\b`)
