package agentbus_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
)

func TestBusRoutesQuery(t *testing.T) {
	bus := agentbus.New(3)
	bus.Register("expert-001", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "expert-001",
			Answer:    "The attestation check is missing because...",
			Facts:     []string{"verify.rs:42 has no timestamp check"},
		}, nil
	})

	resp, err := bus.Ask(context.Background(), agentbus.Query{
		QueryID:   "q-001",
		FromAgent: "verifier-001",
		ToAgent:   "expert-001",
		Kind:      "clarify",
		Question:  "Why do you think attestation is missing?",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.FromAgent != "expert-001" {
		t.Fatalf("expected from expert-001, got %s", resp.FromAgent)
	}
	if len(resp.Facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(resp.Facts))
	}
}

func TestBusUnknownAgent(t *testing.T) {
	bus := agentbus.New(3)
	_, err := bus.Ask(context.Background(), agentbus.Query{
		QueryID: "q-001",
		ToAgent: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestBusRoundLimit(t *testing.T) {
	bus := agentbus.New(2)
	bus.Register("target", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{QueryID: q.QueryID, FromAgent: "target", Answer: "ok"}, nil
	})

	caseID := "case-001"

	_, err := bus.AskForCase(context.Background(), caseID, agentbus.Query{
		QueryID: "q-1", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q1",
	})
	if err != nil {
		t.Fatalf("round 1 failed: %v", err)
	}

	_, err = bus.AskForCase(context.Background(), caseID, agentbus.Query{
		QueryID: "q-2", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q2",
	})
	if err != nil {
		t.Fatalf("round 2 failed: %v", err)
	}

	_, err = bus.AskForCase(context.Background(), caseID, agentbus.Query{
		QueryID: "q-3", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q3",
	})
	if err == nil {
		t.Fatal("expected error for round limit exceeded")
	}
}

func TestBusDialogPersistence(t *testing.T) {
	bus := agentbus.New(5)
	bus.Register("target", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{QueryID: q.QueryID, FromAgent: "target", Answer: "answer"}, nil
	})

	_, _ = bus.AskForCase(context.Background(), "case-001", agentbus.Query{
		QueryID: "q-1", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q1",
	})

	dialog := bus.GetDialog("case-001")
	if dialog == nil {
		t.Fatal("expected dialog for case-001")
	}
	if len(dialog.Rounds) != 1 {
		t.Fatalf("expected 1 round, got %d", len(dialog.Rounds))
	}
	if dialog.Rounds[0].Query.Question != "q1" {
		t.Fatalf("unexpected question: %s", dialog.Rounds[0].Query.Question)
	}

	bus.ResetDialog("case-001")
	dialog = bus.GetDialog("case-001")
	if dialog != nil && len(dialog.Rounds) != 0 {
		t.Fatal("expected empty dialog after reset")
	}
}
