package agentbus

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
)

func busQueries(evs []events.Event) []events.Event {
	var out []events.Event
	for _, ev := range evs {
		if ev.Type == events.TypeBusQuery {
			out = append(out, ev)
		}
	}
	return out
}

// The reasoning the four review agents do IS the inter-agent dialogue. Before
// this event the stream held only the bus's refusals and its over-long
// answers — run-b's 21 answered queries produced 11 events, every one of them
// a truncation notice.
func TestBus_AnsweredQueryIsRecorded(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.SetBlobs(h.Blobs)
	b.Register("expert-001", okHandler)

	if _, err := b.AskForCase(context.Background(), "case-001", Query{
		QueryID:   "verifier-inv-001-r0-q0",
		FromAgent: "verifier-001",
		ToAgent:   "expert-001",
		Kind:      "grep",
		Question:  "Where is shdr_load_pub_key defined?",
		Evidence:  "core/crypto/signed_hdr.c:253",
	}); err != nil {
		t.Fatal(err)
	}

	got := busQueries(h.Events())
	if len(got) != 1 {
		t.Fatalf("want one %s event, got %d", events.TypeBusQuery, len(got))
	}
	ev := got[0]
	if ev.Agent != "verifier-001" || ev.ToAgent != "expert-001" || ev.CaseID != "case-001" {
		t.Errorf("event must name who asked whom, about what: %+v", ev)
	}
	if ev.QueryID != "verifier-inv-001-r0-q0" {
		t.Errorf("query_id=%q — it is the join key to the stage's dialog-*.jsonl", ev.QueryID)
	}
	if ev.Kind != "grep" {
		t.Errorf("kind=%q, want grep", ev.Kind)
	}
	if !strings.Contains(ev.Question, "shdr_load_pub_key") {
		t.Errorf("the question must be greppable in the stream, got %q", ev.Question)
	}
	if ev.OriginalBytes == 0 {
		t.Error("answer size must be recorded — it is what the asking agent paid in prompt bytes")
	}
	if ev.ToolArgsBlob == "" || ev.ToolOutputBlob == "" {
		t.Errorf("both bodies must be recoverable: query=%q response=%q", ev.ToolArgsBlob, ev.ToolOutputBlob)
	}
}

// The evidence is what the answering agent was allowed to reason from, so an
// answer cannot be judged without it. An empty Evidence is how an invented
// answer overrode a CodeQL ToolFact on 2026-08-01.
func TestBus_QueryBlobCarriesTheEvidence(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.SetBlobs(h.Blobs)
	b.Register("expert-001", okHandler)

	if _, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "verifier-001", ToAgent: "expert-001",
		Question: "?", Evidence: "THE-EVIDENCE-BODY",
	}); err != nil {
		t.Fatal(err)
	}

	got := busQueries(h.Events())
	if len(got) != 1 {
		t.Fatalf("want one %s event, got %d", events.TypeBusQuery, len(got))
	}
	body := h.Blob(got[0].ToolArgsBlob)
	if !strings.Contains(body, "THE-EVIDENCE-BODY") {
		t.Errorf("the query blob must hold the evidence, got:\n%s", body)
	}
}

// A question is model-authored and unbounded; the stream is grepped, not
// paged. The preview is cut, but the blob still holds all of it.
func TestBus_LongQuestionIsPreviewedNotDropped(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.SetBlobs(h.Blobs)
	b.Register("expert-001", okHandler)

	tail := "THE-TAIL-OF-THE-QUESTION"
	question := strings.Repeat("x", questionPreview*2) + tail
	if _, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "verifier-001", ToAgent: "expert-001",
		Question: question, Evidence: "e",
	}); err != nil {
		t.Fatal(err)
	}

	got := busQueries(h.Events())
	if len(got) != 1 {
		t.Fatalf("want one %s event, got %d", events.TypeBusQuery, len(got))
	}
	if n := len(got[0].Question); n > questionPreview+4 {
		t.Errorf("inlined question is %d bytes, want it bounded at %d", n, questionPreview)
	}
	if !strings.Contains(h.Blob(got[0].ToolArgsBlob), tail) {
		t.Error("the full question must survive in the blob")
	}
}

// A refused query is not an answered one. Recording both would make the
// stream say the bus did work it did not do.
func TestBus_RefusedQueryEmitsNoAnsweredEvent(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.Register("expert-001", okHandler)

	if _, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "verifier-001", ToAgent: "fact-layer", Question: "?", Evidence: "e",
	}); err == nil {
		t.Fatal("asking an unregistered agent must fail")
	}
	if got := busQueries(h.Events()); len(got) != 0 {
		t.Errorf("a refusal produced %d %s events: %+v", len(got), events.TypeBusQuery, got)
	}
}

// Ask is the non-case entry point and was equally unrecorded.
func TestBus_AskRecordsToo(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.Register("expert-001", okHandler)

	if _, err := b.Ask(context.Background(), Query{
		FromAgent: "verifier-001", ToAgent: "expert-001", Question: "?", Evidence: "e",
	}); err != nil {
		t.Fatal(err)
	}
	if got := busQueries(h.Events()); len(got) != 1 {
		t.Fatalf("want one %s event from Ask, got %d", events.TypeBusQuery, len(got))
	}
}

// A capped answer produces both events, and the answered one reports the
// size the asking agent was actually shown — pairing the two is how the cost
// of a cut is measured.
func TestBus_CappedAnswerRecordsBothSizes(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.SetBlobs(h.Blobs)
	b.Register("scanner-001", floodHandler(100_000))

	if _, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "verifier-001", ToAgent: "scanner-001", Question: "?", Evidence: "e",
	}); err != nil {
		t.Fatal(err)
	}

	answered := busQueries(h.Events())
	if len(answered) != 1 {
		t.Fatalf("want one %s event, got %d", events.TypeBusQuery, len(answered))
	}
	var cut events.Event
	for _, ev := range h.Events() {
		if ev.Type == events.TypeBusResponseTruncated {
			cut = ev
		}
	}
	if cut.Type == "" {
		t.Fatal("a 100k answer must also report a truncation")
	}
	if answered[0].OriginalBytes >= cut.OriginalBytes {
		t.Errorf("bus_query must report the capped size (%d), below the pre-cap size (%d)",
			answered[0].OriginalBytes, cut.OriginalBytes)
	}
}
