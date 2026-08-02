package agentbus

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

type AgentHandler func(ctx context.Context, q Query) (Response, error)

type Bus struct {
	mu        sync.Mutex
	handlers  map[string]AgentHandler
	dialogs   map[string]*Dialog
	maxRounds int

	// rec and runID are optional: a Bus built without them records nothing,
	// which keeps New(maxRounds) working for every existing caller.
	rec   events.Recorder
	runID string
	// blobs is where an over-long answer's full body is kept when it is
	// capped. Optional for the same reason as rec — without it the cap still
	// applies and the notice still says so, it just cannot name a location.
	blobs *events.BlobStore
	// cap bounds an answer's bytes. Zero means DefaultResponseCap; a caller
	// that genuinely wants no limit must say so with a negative value, so
	// "unbounded" is never something a zero value drifts into.
	cap int
}

// SetRecorder makes refused queries visible in the run's event stream.
func (b *Bus) SetRecorder(rec events.Recorder, runID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rec, b.runID = rec, runID
}

// SetBlobs gives the bus somewhere to keep the full body of an answer it had
// to cap, so the notice in the prompt can name a location a human can open.
func (b *Bus) SetBlobs(blobs *events.BlobStore) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blobs = blobs
}

// responseCap is the effective byte cap for one answer.
func (b *Bus) responseCap() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cap == 0 {
		return DefaultResponseCap
	}
	return b.cap
}

// bound applies the response cap, persisting the full body if there is a
// blob store and recording the cut either way. An answer that reaches a
// prompt uncapped is how one 82 MB reply killed a run on 2026-08-02; an
// answer that is cut without a record is how nobody would have known.
func (b *Bus) bound(q Query, caseID string, resp Response) Response {
	limit := b.responseCap()
	if responseBytes(resp) <= limit {
		return resp
	}

	b.mu.Lock()
	blobs, rec, runID := b.blobs, b.rec, b.runID
	b.mu.Unlock()

	// Persist first: the notice should name the location it was written to,
	// so the ref in the prompt is one a reader can actually follow.
	var ref string
	if blobs != nil {
		if r, err := blobs.WriteString(renderFull(resp)); err == nil {
			ref = r
		}
	}
	capped, info := capResponse(resp, limit, ref)
	if rec != nil {
		_ = rec.Emit(events.BusResponseTruncated(runID, q.FromAgent, q.ToAgent, caseID,
			info.OriginalBytes, info.Limit, ref))
	}
	return capped
}

// Names returns the sorted list of registered agent names. to_agent is a
// closed vocabulary, and the arbiter's prompt never published it — so the
// model could only guess. Across six runs it guessed 72 times and was right
// zero times, reaching for "fact-layer", "Investigator" and "CryptoAnalyzer",
// and missing the registered expert-001 by writing "Expert".
func (b *Bus) Names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.handlers))
	for name := range b.handlers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// VocabularyNote is the sentence a prompt appends to publish to_agent's
// closed vocabulary. It returns "" when nothing is registered, so a caller
// can append it unconditionally.
//
// It lives here rather than in each asking agent because the arbiter got it
// and the verifier did not — and the verifier then spent all four of its
// bus queries on run 44362-vuln-p9 asking "fact-layer", an endpoint that has
// never existed. Every one was refused; the events are in that run's
// events.jsonl. A second copy of this sentence is a second chance to have
// only one of them.
func (b *Bus) VocabularyNote() string {
	names := b.Names()
	if len(names) == 0 {
		return ""
	}
	return "\n\nto_agent MUST be exactly one of: " + strings.Join(names, ", ") +
		". Any other value is refused and the query is lost — there is no fact layer, " +
		"investigator or shell tool reachable this way."
}

// questionPreview bounds how much of a question is inlined in the event.
// The question is model-authored and unbounded; the event stream is grepped,
// not paged. The full text is in the query blob.
const questionPreview = 1024

// answered records a query that was answered, with both bodies in blobs.
//
// It is the counterpart to refused. Recording only refusals produced an event
// stream that could show every way the bus failed and nothing it achieved:
// run-b's 21 answered queries left 11 events, all of them truncation notices.
func (b *Bus) answered(q Query, caseID string, resp Response, durationMs int64) {
	b.mu.Lock()
	rec, runID, blobs := b.rec, b.runID, b.blobs
	b.mu.Unlock()
	if rec == nil {
		return
	}

	var queryBlob, responseBlob string
	if blobs != nil {
		// The query body is question plus evidence: the evidence is what the
		// answering agent was allowed to reason from, so an answer cannot be
		// judged without it.
		if ref, err := blobs.WriteString(q.Question + "\n\n--- evidence ---\n" + q.Evidence); err == nil {
			queryBlob = ref
		}
		if ref, err := blobs.WriteString(renderFull(resp)); err == nil {
			responseBlob = ref
		}
	}

	question := q.Question
	if len(question) > questionPreview {
		question = question[:questionPreview] + "…"
	}
	_ = rec.Emit(events.BusQuery(runID, q.FromAgent, q.ToAgent, caseID,
		q.QueryID, q.Kind, question, responseBytes(resp), durationMs,
		queryBlob, responseBlob))
}

// refused records a query that went unanswered. Both an unregistered target
// and a handler that errored are refusals from the asking agent's point of
// view; before this they reached the model as one line of prose and left no
// trace, which is why the arbiter's own stated reason for capping findings at
// needs_review was unfindable in events.jsonl.
func (b *Bus) refused(q Query, caseID, reason string) {
	b.mu.Lock()
	rec, runID := b.rec, b.runID
	b.mu.Unlock()
	if rec == nil {
		return
	}
	_ = rec.Emit(events.BusQueryFailed(runID, q.FromAgent, q.ToAgent, caseID, reason))
}

func New(maxRounds int) *Bus {
	if maxRounds <= 0 {
		maxRounds = 3
	}
	return &Bus{
		handlers:  make(map[string]AgentHandler),
		dialogs:   make(map[string]*Dialog),
		maxRounds: maxRounds,
	}
}

func (b *Bus) Register(agentName string, handler AgentHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[agentName] = handler
}

func (b *Bus) Ask(ctx context.Context, q Query) (Response, error) {
	b.mu.Lock()
	handler, ok := b.handlers[q.ToAgent]
	b.mu.Unlock()
	if !ok {
		b.refused(q, "", "unknown agent: "+q.ToAgent+"; registered: "+strings.Join(b.Names(), ", "))
		return Response{}, fmt.Errorf("unknown agent: %s", q.ToAgent)
	}
	start := time.Now()
	resp, err := handler(ctx, q)
	if err != nil {
		return Response{}, err
	}
	bounded := b.bound(q, "", resp)
	b.answered(q, "", bounded, time.Since(start).Milliseconds())
	return bounded, nil
}

func (b *Bus) AskForCase(ctx context.Context, caseID string, q Query) (Response, error) {
	// The quota is per (case, asking agent). Keyed on the case alone, the
	// verifier, arbiter and curator drew from one shared budget: once
	// scanner-001 started answering, the verifier spent it and the arbiter
	// hit the limit before reaching the rollback question at all — it said so
	// in its own finding. One agent running out must not silence the next.
	key := dialogKey(caseID, q.FromAgent)
	b.mu.Lock()
	dialog, exists := b.dialogs[key]
	if !exists {
		dialog = &Dialog{CaseID: caseID}
		b.dialogs[key] = dialog
	}
	if len(dialog.Rounds) >= b.maxRounds {
		b.mu.Unlock()
		b.refused(q, caseID, fmt.Sprintf("dialog round limit (%d) reached", b.maxRounds))
		return Response{}, fmt.Errorf("dialog round limit (%d) reached for case %s", b.maxRounds, caseID)
	}
	handler, ok := b.handlers[q.ToAgent]
	b.mu.Unlock()

	if !ok {
		b.refused(q, caseID, "unknown agent: "+q.ToAgent+"; registered: "+strings.Join(b.Names(), ", "))
		return Response{}, fmt.Errorf("unknown agent: %s", q.ToAgent)
	}

	start := time.Now()
	resp, err := handler(ctx, q)
	if err != nil {
		b.refused(q, caseID, "handler error: "+err.Error())
		return Response{}, fmt.Errorf("agent %s: %w", q.ToAgent, err)
	}

	// Cap before the dialog records it: the transcript should hold what the
	// asking agent was actually shown, not a fuller version it never saw.
	resp = b.bound(q, caseID, resp)
	b.answered(q, caseID, resp, time.Since(start).Milliseconds())

	b.mu.Lock()
	dialog.Rounds = append(dialog.Rounds, Round{Query: q, Response: resp})
	b.mu.Unlock()

	return resp, nil
}

// dialogKey scopes a dialog to one case AND one asking agent. Keyed on the
// case alone, the three stages that use the bus shared a single budget and a
// single history — so ResetDialog from one stage wiped another's transcript,
// and the first stage to spend the quota silenced the rest.
func dialogKey(caseID, fromAgent string) string { return caseID + "\x00" + fromAgent }

// GetDialog returns fromAgent's transcript for this case.
func (b *Bus) GetDialog(caseID, fromAgent string) *Dialog {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.dialogs[dialogKey(caseID, fromAgent)]
	if !ok {
		return nil
	}
	return d
}

// ResetDialog clears fromAgent's budget and transcript for this case.
func (b *Bus) ResetDialog(caseID, fromAgent string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.dialogs, dialogKey(caseID, fromAgent))
}

func (b *Bus) MaxRounds() int {
	return b.maxRounds
}
