package agentbus

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
)

// floodHandler answers with n facts, the way scanner-001 does when its
// keyword extraction matches most of a repository.
func floodHandler(n int) AgentHandler {
	return func(context.Context, Query) (Response, error) {
		facts := make([]string, n)
		for i := range facts {
			facts[i] = ".checkpatch.conf:2 --no-tree --max-line-length=80 --ignore=CAMELCASE"
		}
		return Response{Answer: "Found many results", Facts: facts}, nil
	}
}

// The bus was the one tool boundary with no limit. On 2026-08-02 scanner-001,
// searching a 3291-file checkout with the asking question split into
// keywords, returned every matching line; the verifier's follow-up prompt
// reached 82,191,625 bytes and the request never came back. Three retries at
// ten minutes each were spent before the run died.
func TestBus_AnswerIsCappedBeforeItReachesTheAsker(t *testing.T) {
	b := New(3)
	b.Register("scanner-001", floodHandler(200_000))

	resp, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "verifier-001", ToAgent: "scanner-001", Question: "?", Evidence: "e",
	})
	if err != nil {
		t.Fatalf("AskForCase: %v", err)
	}
	if got := responseBytes(resp); got > DefaultResponseCap*2 {
		t.Fatalf("answer reached the asker at %d bytes, cap is %d", got, DefaultResponseCap)
	}
	if len(resp.Facts) >= 200_000 {
		t.Fatalf("facts = %d, want them cut", len(resp.Facts))
	}
}

// A cut that reads as a complete answer is worse than no answer: the model
// acts on a partial result believing it has the whole one. The notice has to
// say so where the model reads it.
func TestCapResponse_SaysItIsAPreviewAndHowMuchIsMissing(t *testing.T) {
	facts := make([]string, 5000)
	for i := range facts {
		facts[i] = "core/kernel/ree_fs_ta.c:314 check_update_version"
	}
	capped, info := capResponse(Response{Answer: "Found 5000 results", Facts: facts}, 4096, "sha256:abc123")

	for _, want := range []string{"PREVIEW ONLY", "NOT shown", "not read the absence", "sha256:abc123"} {
		if !strings.Contains(capped.Answer, want) {
			t.Errorf("notice must contain %q so the cut cannot be mistaken for a complete answer:\n%s", want, capped.Answer)
		}
	}
	if info.OriginalBytes == 0 || info.Limit != 4096 {
		t.Errorf("TruncationInfo must carry the sizes for the record: %+v", info)
	}
	// The full body is kept so the notice's reference resolves to something.
	if !strings.Contains(info.Full, "ree_fs_ta.c:314") || len(info.Full) <= len(capped.Answer) {
		t.Error("TruncationInfo.Full must be the uncut body")
	}
}

// Facts are cut whole. Half of "path:line" is not a shorter fact, it is a
// wrong one — and a citation validator downstream would read it as a
// fabricated location.
func TestCapResponse_NeverCutsAFactInHalf(t *testing.T) {
	const fact = "core/crypto/signed_hdr.c:262 shdr_load_pub_key"
	facts := make([]string, 1000)
	for i := range facts {
		facts[i] = fact
	}
	capped, _ := capResponse(Response{Answer: "x", Facts: facts}, 512, "")
	for _, f := range capped.Facts {
		if f != fact {
			t.Fatalf("fact was cut mid-string: %q", f)
		}
	}
}

// An answer inside the cap must pass through untouched — no notice, no
// wrapper. Most answers are small and must not be made to look partial.
func TestCapResponse_SmallAnswerIsUnchanged(t *testing.T) {
	in := Response{Answer: "check_update_version is called at ree_fs_ta.c:314", Facts: []string{"a", "b"}}
	out, info := capResponse(in, DefaultResponseCap, "")
	if out.Answer != in.Answer || len(out.Facts) != 2 {
		t.Fatalf("a small answer must pass through unchanged: %+v", out)
	}
	if info.OriginalBytes != 0 {
		t.Errorf("nothing was cut, so nothing should be reported: %+v", info)
	}
}

// A cut must leave a record. A cap that silently trims relevant evidence and
// one that trims a handler's noise are indistinguishable from the outside;
// the event with both sizes is what makes the difference measurable.
func TestBus_TruncationIsRecordedWithItsSizes(t *testing.T) {
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

	var got []events.Event
	for _, ev := range h.Events() {
		if ev.Type == events.TypeBusResponseTruncated {
			got = append(got, ev)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one %s event, got %d", events.TypeBusResponseTruncated, len(got))
	}
	ev := got[0]
	if ev.OriginalBytes <= ev.MaxOutputBytes {
		t.Errorf("original_bytes=%d must exceed the cap=%d", ev.OriginalBytes, ev.MaxOutputBytes)
	}
	if ev.Agent != "verifier-001" || ev.ToAgent != "scanner-001" || ev.CaseID != "case-001" {
		t.Errorf("event must name who asked whom, about what: %+v", ev)
	}
	if ev.ToolOutputBlob == "" {
		t.Error("the full body must be recoverable from the event")
	}
}

// Nothing was cut, nothing is recorded — otherwise the metric measures
// traffic instead of loss.
func TestBus_NoEventWhenNothingIsCut(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-a")
	b.Register("expert-001", okHandler)

	if _, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "verifier-001", ToAgent: "expert-001", Question: "?", Evidence: "e",
	}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range h.Events() {
		if ev.Type == events.TypeBusResponseTruncated {
			t.Fatalf("a small answer must not report a truncation: %+v", ev)
		}
	}
}
