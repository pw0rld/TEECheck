package llm

import (
	"context"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// RecordingOptions carries everything an llm_call_* event needs. It is
// supplied once, at wiring time, by whoever owns the run's event stream
// (today: internal/pipeline), so agents keep receiving a plain llm.Client
// and never learn about events at all.
type RecordingOptions struct {
	// RunID and AgentID attribute the call. Both are required: an event
	// that cannot be attributed to a run and an agent is not evidence,
	// it is noise.
	RunID   string
	AgentID string

	// Model is recorded verbatim on both events. Empty is tolerated —
	// some standalone entry points do not know the model name.
	Model string

	// Blobs receives the full prompt and response bodies; Events
	// receives the two events carrying the resulting refs.
	Blobs  *events.BlobStore
	Events events.Recorder
}

// complete reports whether the options carry enough to record anything
// useful. Anything less degrades to a plain pass-through rather than a
// partially-recorded stream: agents are constructed in tests with no
// event plumbing at all, and instrumentation must never be the reason a
// run fails.
func (o RecordingOptions) complete() bool {
	return o.RunID != "" && o.AgentID != "" && o.Blobs != nil && o.Events != nil
}

// recordingClient decorates a Client so every Generate leaves an
// llm_call_started / llm_call_completed pair in the run's event stream,
// with the full prompt and response bodies in the content-addressed blob
// store.
//
// It exists because thirteen of the fourteen production call sites
// recorded nothing: when a stage failed on a malformed reply, the only
// evidence was a truncated excerpt inside an error string, and questions
// like "how long was the reply", "did it hit the token cap", "what
// exactly did we send" were unanswerable. Every agent receives its
// client by injection and Client has a single method, so one decorator
// covers all of them without touching a single call site.
//
// The decorator is deliberately placed OUTSIDE the retry layer (see
// NewClient): one logical request must produce exactly one event pair,
// not one per transport retry.
//
// It holds no state, so it is safe for concurrent use whenever the
// wrapped client, recorder and blob store are.
type recordingClient struct {
	inner Client
	opts  RecordingOptions
}

// NewRecordingClient wraps inner so its calls are recorded. If opts is
// missing any of run id, agent id, blob store or recorder, inner is
// returned unchanged — callers get a working client either way.
func NewRecordingClient(inner Client, opts RecordingOptions) Client {
	if inner == nil || !opts.complete() {
		return inner
	}
	return &recordingClient{inner: inner, opts: opts}
}

func (c *recordingClient) Generate(ctx context.Context, req GenerateRequest) (GenerateResponse, error) {
	o := c.opts

	// Round is planner-specific: it identifies one iteration of the
	// planner's investigate loop. A stage agent has no such loop, so it
	// reports 0, which `omitempty` drops from the JSON entirely. The
	// alternative — synthesising a round number — would publish a value
	// consumers cannot distinguish from a real planner round.
	const noRound = 0

	_ = o.Events.Emit(events.LLMCallStarted(o.RunID, o.AgentID, o.Model, noRound))

	resp, genErr := c.inner.Generate(ctx, req)

	prompt := renderPrompt(req)
	body := resp.Text
	if body == "" {
		// A provider that returned an unparsed body but no extracted
		// text still tells us what happened; keep it.
		body = resp.Raw
	}

	promptBlob := writeBlob(o.Blobs, prompt)
	responseBlob := writeBlob(o.Blobs, body)

	// The wire bodies are kept in addition, never instead. The two above
	// are for reading; these are the exact bytes, and they are the only
	// place finish_reason, response_format and any field the parser does
	// not read survive. They are written on the failure path too — that is
	// the call someone will be diagnosing.
	wireRequestBlob := writeBlob(o.Blobs, resp.RawRequest)
	wireResponseBlob := writeBlob(o.Blobs, resp.Raw)

	tokensIn, tokensOut := resp.Usage.PromptTokens, resp.Usage.CompletionTokens
	if genErr == nil && tokensIn == 0 && tokensOut == 0 {
		// Provider reported no usage (older OpenAI-compatible endpoints,
		// streamed responses). Fall back to the same crude ~4
		// chars/token estimate the planner uses so token accounting
		// stays comparable across agents.
		tokensIn = len(prompt) / 4
		tokensOut = len(body) / 4
	}
	// On the error path the estimate is deliberately NOT applied: a call
	// that failed may never have reached the provider, and an invented
	// count would inflate the run's token accounting with tokens nobody
	// was billed for.

	done := events.LLMCallCompleted(o.RunID, o.AgentID, o.Model, noRound, tokensIn, tokensOut, promptBlob, responseBlob).
		WithWireBodies(wireRequestBlob, wireResponseBlob)
	if genErr != nil {
		done.Error = genErr.Error()
	}
	_ = o.Events.Emit(done)

	// The inner result is returned untouched, errors included — the
	// decorator observes, it does not intervene.
	return resp, genErr
}

// writeBlob persists body and returns its ref, or "" if body is empty or
// the store rejected it. A blob we failed to write must not abort the
// call the blob was describing.
func writeBlob(store *events.BlobStore, body string) string {
	if body == "" {
		return ""
	}
	ref, err := store.WriteString(body)
	if err != nil {
		return ""
	}
	return ref
}

// renderPrompt flattens a request into the single text body stored as
// the prompt blob: the system prompt, then each message tagged with its
// role. The separator mirrors the planner's existing prompt blobs so a
// reader sees the same shape whichever agent produced the call.
func renderPrompt(req GenerateRequest) string {
	var b strings.Builder
	b.WriteString(req.SystemPrompt)
	for _, m := range req.Messages {
		b.WriteString("\n\n---\n\n")
		b.WriteString(m.Role)
		b.WriteString(":\n")
		b.WriteString(m.Content)
	}
	return b.String()
}
