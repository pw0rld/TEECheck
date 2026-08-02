package llm

import (
	"errors"
	"fmt"
)

// MaxRequestBytes bounds the total prompt an agent may send in one call.
//
// This is a guardrail, not a budget. Any request approaching it is already a
// defect upstream — the caps on the tools that feed a prompt are what keep it
// small, and they are set far below this. Its job is to make that defect say
// what it is.
//
// On 2026-08-02 a verifier follow-up reached 82,191,625 bytes because one bus
// answer returned a repository's worth of matched lines. The API never sent
// response headers, so it surfaced as "context deadline exceeded (Client.
// Timeout exceeded while awaiting headers)" — indistinguishable from a network
// fault. It was classified transient and retried three times at ten minutes
// each: thirty minutes spent, the run lost, and the failure blamed on the
// provider. It had already happened once before under the same misreading.
//
// 8 MiB is roughly two million tokens — far past any model's window, so
// nothing that could have succeeded is refused here.
const MaxRequestBytes = 8 << 20

// ErrRequestTooLarge is returned instead of sending a prompt that cannot
// succeed. It is deliberately NOT transient: retrying a request that is too
// large reproduces the same failure at the same cost.
var ErrRequestTooLarge = errors.New("llm request too large")

// requestBytes is the whole payload: system prompt plus every message.
func requestBytes(req GenerateRequest) int {
	n := len(req.SystemPrompt)
	for _, m := range req.Messages {
		n += len(m.Content) + len(m.Role)
	}
	return n
}

// checkRequestSize refuses an impossible request with an error that names the
// largest message, so the caller learns which input grew rather than only
// that the total did.
func checkRequestSize(req GenerateRequest) error {
	total := requestBytes(req)
	if total <= MaxRequestBytes {
		return nil
	}
	worst, worstIdx := 0, -1
	for i, m := range req.Messages {
		if len(m.Content) > worst {
			worst, worstIdx = len(m.Content), i
		}
	}
	where := fmt.Sprintf("system prompt (%d bytes)", len(req.SystemPrompt))
	if worstIdx >= 0 && worst > len(req.SystemPrompt) {
		where = fmt.Sprintf("message %d/%d, role %q (%d bytes)",
			worstIdx+1, len(req.Messages), req.Messages[worstIdx].Role, worst)
	}
	return fmt.Errorf("%w: %d bytes exceeds the %d-byte limit; largest part is %s — "+
		"something upstream returned an unbounded result",
		ErrRequestTooLarge, total, MaxRequestBytes, where)
}
