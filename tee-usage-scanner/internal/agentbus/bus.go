package agentbus

import (
	"context"
	"fmt"
	"sync"
)

type AgentHandler func(ctx context.Context, q Query) (Response, error)

type Bus struct {
	mu        sync.Mutex
	handlers  map[string]AgentHandler
	dialogs   map[string]*Dialog
	maxRounds int
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
		return Response{}, fmt.Errorf("dialog round limit (%d) reached for case %s", b.maxRounds, caseID)
	}
	handler, ok := b.handlers[q.ToAgent]
	b.mu.Unlock()

	if !ok {
		return Response{}, fmt.Errorf("unknown agent: %s", q.ToAgent)
	}

	resp, err := handler(ctx, q)
	if err != nil {
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
