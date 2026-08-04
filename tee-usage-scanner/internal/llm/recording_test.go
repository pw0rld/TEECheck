package llm_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// recInner is a scriptable llm.Client standing in for a provider.
type recInner struct {
	resp  llm.GenerateResponse
	err   error
	calls []llm.GenerateRequest
}

func (r *recInner) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	r.calls = append(r.calls, req)
	return r.resp, r.err
}

// capRecorder collects emitted events in memory.
type capRecorder struct{ got []events.Event }

func (c *capRecorder) Emit(e events.Event) error { c.got = append(c.got, e); return nil }
func (c *capRecorder) Close() error              { return nil }

func (c *capRecorder) byType(t string) []events.Event {
	var out []events.Event
	for _, e := range c.got {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// readBlob resolves a "sha256:<hex>" reference against the store directory.
func readBlob(t *testing.T, dir, ref string) string {
	t.Helper()
	if !strings.HasPrefix(ref, "sha256:") {
		t.Fatalf("blob ref %q is not a sha256 reference", ref)
	}
	body, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(ref, "sha256:")+".txt"))
	if err != nil {
		t.Fatalf("read blob %s: %v", ref, err)
	}
	return string(body)
}

func newRecordingHarness(t *testing.T, inner llm.Client) (llm.Client, *capRecorder, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := events.NewBlobStore(dir)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	rec := &capRecorder{}
	c := llm.NewRecordingClient(inner, llm.RecordingOptions{
		RunID:   "run-42",
		AgentID: "challenger-001",
		Model:   "glm-4.6",
		Blobs:   store,
		Events:  rec,
	})
	return c, rec, dir
}

// TestRecordingClient_EmitsOneStartedOneCompleted is the core contract: a
// single Generate produces exactly one started and one completed event,
// attributed to the configured agent and model.
func TestRecordingClient_EmitsOneStartedOneCompleted(t *testing.T) {
	inner := &recInner{resp: llm.GenerateResponse{Text: "hello", Raw: "hello"}}
	c, rec, _ := newRecordingHarness(t, inner)

	if _, err := c.Generate(context.Background(), llm.GenerateRequest{
		SystemPrompt: "sys",
		Messages:     []llm.Message{{Role: "user", Content: "q"}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	started := rec.byType(events.TypeLLMCallStarted)
	completed := rec.byType(events.TypeLLMCallCompleted)
	if len(started) != 1 {
		t.Fatalf("llm_call_started count = %d, want 1 (events: %+v)", len(started), rec.got)
	}
	if len(completed) != 1 {
		t.Fatalf("llm_call_completed count = %d, want 1 (events: %+v)", len(completed), rec.got)
	}
	if len(rec.got) != 2 {
		t.Fatalf("emitted %d events, want exactly 2", len(rec.got))
	}
	// started must precede completed — a consumer pairs them in order.
	if rec.got[0].Type != events.TypeLLMCallStarted {
		t.Errorf("first event = %s, want %s", rec.got[0].Type, events.TypeLLMCallStarted)
	}
	for _, e := range rec.got {
		if e.RunID != "run-42" {
			t.Errorf("%s RunID = %q, want run-42", e.Type, e.RunID)
		}
		if e.Agent != "challenger-001" {
			t.Errorf("%s Agent = %q, want challenger-001", e.Type, e.Agent)
		}
		if e.Model != "glm-4.6" {
			t.Errorf("%s Model = %q, want glm-4.6", e.Type, e.Model)
		}
		// Round is planner-only. A stage agent has no round; it must
		// report 0 so `omitempty` drops the field rather than
		// publishing a number a consumer would read as a real round.
		if e.Round != 0 {
			t.Errorf("%s Round = %d, want 0 for a non-round-based agent", e.Type, e.Round)
		}
	}
}

// TestRecordingClient_BlobsHoldFullBodies asserts the refs on the completed
// event resolve to the complete prompt and response — not merely that a ref
// is non-empty. This is the assertion that turns "unterminated json object"
// into a diagnosable failure.
func TestRecordingClient_BlobsHoldFullBodies(t *testing.T) {
	longReply := strings.Repeat("{\"findings\":[]}", 400)
	inner := &recInner{resp: llm.GenerateResponse{Text: longReply, Raw: longReply}}
	c, rec, dir := newRecordingHarness(t, inner)

	req := llm.GenerateRequest{
		SystemPrompt: "SYSTEM-PROMPT-BODY",
		Messages: []llm.Message{
			{Role: "user", Content: "USER-TURN-ONE"},
			{Role: "assistant", Content: "ASSISTANT-TURN"},
		},
	}
	if _, err := c.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	done := rec.byType(events.TypeLLMCallCompleted)[0]
	if done.PromptBlob == "" || done.ResponseBlob == "" {
		t.Fatalf("blob refs empty: prompt=%q response=%q", done.PromptBlob, done.ResponseBlob)
	}
	if done.PromptBlob == done.ResponseBlob {
		t.Fatalf("prompt and response resolved to the same blob %q", done.PromptBlob)
	}

	gotPrompt := readBlob(t, dir, done.PromptBlob)
	for _, want := range []string{"SYSTEM-PROMPT-BODY", "USER-TURN-ONE", "ASSISTANT-TURN"} {
		if !strings.Contains(gotPrompt, want) {
			t.Errorf("prompt blob missing %q; got:\n%s", want, gotPrompt)
		}
	}
	if gotResp := readBlob(t, dir, done.ResponseBlob); gotResp != longReply {
		t.Errorf("response blob len = %d, want %d (full body, untruncated)", len(gotResp), len(longReply))
	}
}

// TestRecordingClient_ErrorStillCompletes is the case that motivated the
// change: a failed call must still leave a completed event carrying the
// error, and the caller must receive the error unchanged.
func TestRecordingClient_ErrorStillCompletes(t *testing.T) {
	boom := errors.New("context deadline exceeded")
	inner := &recInner{
		// A provider that errored after producing a partial body: the
		// partial must still be persisted, that is the evidence.
		resp: llm.GenerateResponse{Text: "PARTIAL-BODY"},
		err:  boom,
	}
	c, rec, dir := newRecordingHarness(t, inner)

	_, err := c.Generate(context.Background(), llm.GenerateRequest{
		SystemPrompt: "sys",
		Messages:     []llm.Message{{Role: "user", Content: "PROMPT-ON-FAILURE"}},
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Generate err = %v, want the inner error unchanged", err)
	}

	completed := rec.byType(events.TypeLLMCallCompleted)
	if len(completed) != 1 {
		t.Fatalf("llm_call_completed count = %d on error path, want 1", len(completed))
	}
	if completed[0].Error != boom.Error() {
		t.Errorf("completed.Error = %q, want %q", completed[0].Error, boom.Error())
	}
	if len(rec.byType(events.TypeLLMCallStarted)) != 1 {
		t.Errorf("llm_call_started missing on error path")
	}
	if completed[0].PromptBlob == "" {
		t.Fatalf("prompt blob not persisted on error path — the prompt is unrecoverable")
	}
	if got := readBlob(t, dir, completed[0].PromptBlob); !strings.Contains(got, "PROMPT-ON-FAILURE") {
		t.Errorf("prompt blob = %q, want it to contain the failed prompt", got)
	}
	if completed[0].ResponseBlob == "" {
		t.Fatalf("partial response body not persisted on error path")
	}
	if got := readBlob(t, dir, completed[0].ResponseBlob); got != "PARTIAL-BODY" {
		t.Errorf("response blob = %q, want %q", got, "PARTIAL-BODY")
	}
}

// TestRecordingClient_TokenFallback: a provider reporting zero usage must
// still yield non-zero estimated counts, matching the planner's ~4
// chars/token fallback so accounting stays comparable across agents.
func TestRecordingClient_TokenFallback(t *testing.T) {
	inner := &recInner{resp: llm.GenerateResponse{Text: strings.Repeat("r", 400)}}
	c, rec, _ := newRecordingHarness(t, inner)

	if _, err := c.Generate(context.Background(), llm.GenerateRequest{
		SystemPrompt: strings.Repeat("s", 800),
		Messages:     []llm.Message{{Role: "user", Content: strings.Repeat("u", 800)}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	done := rec.byType(events.TypeLLMCallCompleted)[0]
	if done.TokensIn == 0 {
		t.Errorf("TokensIn = 0, want a non-zero estimate")
	}
	if done.TokensOut == 0 {
		t.Errorf("TokensOut = 0, want a non-zero estimate")
	}
	if done.TokensIn < 300 || done.TokensIn > 600 {
		t.Errorf("TokensIn = %d, want ~4 chars/token over a 1600-char prompt", done.TokensIn)
	}
	if done.TokensOut != 100 {
		t.Errorf("TokensOut = %d, want 100 (400 chars / 4)", done.TokensOut)
	}
}

// TestRecordingClient_PrefersProviderUsage: when the provider reports usage,
// the estimate must not override it.
func TestRecordingClient_PrefersProviderUsage(t *testing.T) {
	inner := &recInner{resp: llm.GenerateResponse{
		Text:  strings.Repeat("r", 4000),
		Usage: llm.Usage{PromptTokens: 11, CompletionTokens: 7},
	}}
	c, rec, _ := newRecordingHarness(t, inner)

	if _, err := c.Generate(context.Background(), llm.GenerateRequest{SystemPrompt: "sys"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	done := rec.byType(events.TypeLLMCallCompleted)[0]
	if done.TokensIn != 11 || done.TokensOut != 7 {
		t.Errorf("tokens = (%d,%d), want provider-reported (11,7)", done.TokensIn, done.TokensOut)
	}
}

// TestRecordingClient_DegradesToPassThrough: agents built with no event
// plumbing must keep working. Each incomplete option set must yield the
// inner client itself, not a wrapper that panics on a nil recorder.
func TestRecordingClient_DegradesToPassThrough(t *testing.T) {
	store, err := events.NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	full := llm.RecordingOptions{RunID: "r", AgentID: "a", Model: "m", Blobs: store, Events: &capRecorder{}}

	cases := map[string]llm.RecordingOptions{
		"nil recorder":   {RunID: "r", AgentID: "a", Blobs: store},
		"nil blob store": {RunID: "r", AgentID: "a", Events: &capRecorder{}},
		"empty run id":   {AgentID: "a", Blobs: store, Events: &capRecorder{}},
		"empty agent id": {RunID: "r", Blobs: store, Events: &capRecorder{}},
		"zero options":   {},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			inner := &recInner{resp: llm.GenerateResponse{Text: "ok"}}
			c := llm.NewRecordingClient(inner, opts)
			resp, err := c.Generate(context.Background(), llm.GenerateRequest{SystemPrompt: "s"})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if resp.Text != "ok" {
				t.Errorf("Text = %q, want the inner response passed through", resp.Text)
			}
			if len(inner.calls) != 1 {
				t.Errorf("inner called %d times, want 1", len(inner.calls))
			}
		})
	}

	// Sanity: the same harness WITH full options does wrap, so the
	// pass-through assertions above are not vacuously true.
	inner := &recInner{resp: llm.GenerateResponse{Text: "ok"}}
	rec := full.Events.(*capRecorder)
	if _, err := llm.NewRecordingClient(inner, full).Generate(context.Background(), llm.GenerateRequest{}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(rec.got) == 0 {
		t.Fatal("fully-configured recording client emitted nothing")
	}
}

// TestRecordingClient_PassesRequestThrough: the decorator must not mutate
// the request or the response on the way through.
func TestRecordingClient_PassesRequestThrough(t *testing.T) {
	inner := &recInner{resp: llm.GenerateResponse{Text: "T", Raw: "R", Usage: llm.Usage{TotalTokens: 3}}}
	c, _, _ := newRecordingHarness(t, inner)

	req := llm.GenerateRequest{
		SystemPrompt: "sys",
		Messages:     []llm.Message{{Role: "user", Content: "q"}},
		Temperature:  0.25,
		JSONMode:     true,
	}
	resp, err := c.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Text != "T" || resp.Raw != "R" || resp.Usage.TotalTokens != 3 {
		t.Errorf("response mutated: %+v", resp)
	}
	if len(inner.calls) != 1 {
		t.Fatalf("inner called %d times, want 1", len(inner.calls))
	}
	if got := inner.calls[0]; got.Temperature != 0.25 || !got.JSONMode || got.SystemPrompt != "sys" {
		t.Errorf("request mutated: %+v", got)
	}
}

// The extracted text answers "what did the model say". It cannot answer
// "was response_format sent", "what was finish_reason", or "did the
// provider return a field the parser ignored" — and on 2026-08-04 a planner
// run died on two consecutive non-JSON replies with none of those
// answerable. The wire bodies are kept in addition, not instead.
func TestRecordingClient_KeepsBothWireBodies(t *testing.T) {
	const wireReq = `{"model":"glm-5.2","response_format":{"type":"json_object"},"messages":[]}`
	const wireResp = `{"choices":[{"message":{"content":"hi"},"finish_reason":"length"}]}`

	inner := &recInner{resp: llm.GenerateResponse{
		Text: "hi", RawRequest: wireReq, Raw: wireResp,
	}}
	c, rec, dir := newRecordingHarness(t, inner)
	if _, err := c.Generate(context.Background(), llm.GenerateRequest{JSONMode: true}); err != nil {
		t.Fatal(err)
	}

	done := rec.byType(events.TypeLLMCallCompleted)[0]
	if done.WireRequestBlob == "" || done.WireResponseBlob == "" {
		t.Fatalf("wire bodies not recorded: request=%q response=%q",
			done.WireRequestBlob, done.WireResponseBlob)
	}
	if got := readBlob(t, dir, done.WireRequestBlob); got != wireReq {
		t.Errorf("request blob = %q, want the exact bytes sent", got)
	}
	if got := readBlob(t, dir, done.WireResponseBlob); got != wireResp {
		t.Errorf("response blob = %q, want the exact bytes received", got)
	}
	// The readable pair still holds the extracted message, not the JSON —
	// the wire bodies are an addition, not a replacement.
	if got := readBlob(t, dir, done.ResponseBlob); got != "hi" {
		t.Errorf("response_blob = %q, want the extracted message", got)
	}
}

// A call that failed is the one someone will be diagnosing. Whatever
// reached the wire before it failed has to survive — a 429 body says why.
func TestRecordingClient_KeepsWireBodiesOnTheErrorPath(t *testing.T) {
	const wireReq = `{"model":"glm-5.2"}`
	const wireResp = `{"error":{"message":"rate limit"}}`

	inner := &recInner{
		resp: llm.GenerateResponse{RawRequest: wireReq, Raw: wireResp},
		err:  errors.New("llm status 429"),
	}
	c, rec, dir := newRecordingHarness(t, inner)
	if _, err := c.Generate(context.Background(), llm.GenerateRequest{}); err == nil {
		t.Fatal("the inner error must propagate")
	}

	done := rec.byType(events.TypeLLMCallCompleted)[0]
	if got := readBlob(t, dir, done.WireResponseBlob); got != wireResp {
		t.Errorf("the provider's error body was dropped: %q", got)
	}
	if got := readBlob(t, dir, done.WireRequestBlob); got != wireReq {
		t.Errorf("the request that failed was dropped: %q", got)
	}
}
