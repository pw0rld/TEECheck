package llm

import (
	"context"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
)

// GenerateJSON calls the LLM, parses the reply into out, and on a PARSE
// failure re-asks exactly once with a corrective notice before giving up.
//
// Why this lives in internal/llm and not internal/agentutil: the helper needs
// both a Client (declared here) and the reply extractor (declared in
// agentutil), and internal/llm/json.go already imports agentutil. A helper
// taking an llm.Client therefore cannot live in agentutil without an import
// cycle. internal/llm is the only package that can see both, and it is where
// every agent already imports its request/response types from.
//
// The bound is ONE re-ask. Format wobble is common — a model wraps its object
// in an array, narrates before it, fences it — and losing a whole stage (and
// with it the run) to one wobble is the wrong trade when the fix costs a
// single extra call. Two malformed replies in a row is a real failure, not
// something to spend budget on, so there is no third attempt and no loop.
//
// A transport error is NOT re-asked: NewClient already wraps every provider in
// a retry layer that owns 5xx/timeout/reset, and re-asking on top of it would
// multiply the calls for a failure this function cannot correct.
//
// Both calls go through the injected client, so a recording decorator
// (recording.go) sees the re-ask exactly like any other call — there is no
// separate path to instrument.
//
// label names the agent in errors ("parse expert json: ..."), keeping the
// message each call site produced before it was migrated here.
func GenerateJSON[T any](ctx context.Context, client Client, label string, req GenerateRequest, out *T) (GenerateResponse, error) {
	resp, err := client.Generate(ctx, req)
	if err != nil {
		return resp, fmt.Errorf("%s llm generate: %w", label, err)
	}
	parseErr := agentutil.UnmarshalJSONObject(resp.Text, out)
	if parseErr == nil {
		return resp, nil
	}

	// One corrective re-ask. The wording follows internal/planner's existing
	// re-ask so the system speaks with one voice to the model: state the
	// rejection, say why, quote the offending reply back, and demand the bare
	// object.
	retryResp, retryErr := client.Generate(ctx, withRejectionNotice(req, parseErr, resp.Text))
	if retryErr != nil {
		// Report the original parse failure, not the transport error on the
		// corrective call: the parse failure is what actually broke, and the
		// re-ask is a recovery attempt, not the event being diagnosed.
		return resp, fmt.Errorf("parse %s json: %w | raw=%s", label, parseErr, truncateForError(resp.Text, 400))
	}
	if err := agentutil.UnmarshalJSONObject(retryResp.Text, out); err != nil {
		return retryResp, fmt.Errorf("parse %s json: %w | raw=%s", label, err, truncateForError(retryResp.Text, 400))
	}
	return retryResp, nil
}

// withRejectionNotice returns a copy of req whose LAST user turn carries the
// corrective notice. It appends to that turn rather than adding a new message
// because verifier and arbiter run multi-turn dialogs (user / assistant /
// user) and an extra trailing user message would break role alternation on
// providers that require it. The message slice is copied so the caller's own
// conversation — which it keeps appending to — is never mutated.
func withRejectionNotice(req GenerateRequest, parseErr error, rejected string) GenerateRequest {
	notice := "\n\n=== YOUR PREVIOUS REPLY WAS REJECTED ===\n" +
		"It was not a JSON object (" + parseErr.Error() + "). Do not narrate, explain, or announce what you are about to do.\n" +
		"Reply with the JSON object described in the response format and NOTHING else — no prose before it, no prose after it, no markdown fence, no array around it.\n" +
		"Your rejected reply began: " + truncateForError(rejected, 200) + "\n"

	out := req
	msgs := make([]Message, len(req.Messages))
	copy(msgs, req.Messages)
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			msgs[i].Content += notice
			out.Messages = msgs
			return out
		}
	}
	out.Messages = append(msgs, Message{Role: "user", Content: notice})
	return out
}
