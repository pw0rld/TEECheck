package agentbus

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

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
}

// SetRecorder makes refused queries visible in the run's event stream.
func (b *Bus) SetRecorder(rec events.Recorder, runID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rec, b.runID = rec, runID
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
	return handler(ctx, q)
}

func (b *Bus) AskForCase(ctx context.Context, caseID string, q Query) (Response, error) {
	b.mu.Lock()
	dialog, exists := b.dialogs[caseID]
	if !exists {
		dialog = &Dialog{CaseID: caseID}
		b.dialogs[caseID] = dialog
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

	resp, err := handler(ctx, q)
	if err != nil {
		b.refused(q, caseID, "handler error: "+err.Error())
		return Response{}, fmt.Errorf("agent %s: %w", q.ToAgent, err)
	}

	b.mu.Lock()
	dialog.Rounds = append(dialog.Rounds, Round{Query: q, Response: resp})
	b.mu.Unlock()

	return resp, nil
}

func (b *Bus) GetDialog(caseID string) *Dialog {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.dialogs[caseID]
	if !ok {
		return nil
	}
	return d
}

func (b *Bus) ResetDialog(caseID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.dialogs, caseID)
}

func (b *Bus) MaxRounds() int {
	return b.maxRounds
}
