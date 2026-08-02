package agentbus

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
)

func okHandler(context.Context, Query) (Response, error) { return Response{Answer: "ok"}, nil }

// to_agent is a closed vocabulary and the arbiter's prompt never published it,
// so the model could only guess. Across six runs it guessed 72 times and was
// right zero times — reaching for "fact-layer", "Investigator",
// "CryptoAnalyzer", "grep" — and missing the registered expert-001 by writing
// "Expert". Names() is what the prompt renders instead.
func TestBus_NamesListsRegisteredAgentsSorted(t *testing.T) {
	b := New(3)
	b.Register("expert-001", okHandler)
	b.Register("challenger-001", okHandler)
	b.Register("scanner-001", okHandler)

	got := b.Names()
	want := []string{"challenger-001", "expert-001", "scanner-001"}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v (sorted)", got, want)
		}
	}
}

// VocabularyNote is the sentence the asking agents' prompts append. Its
// whole job is to name the legal to_agent values, so it must contain every
// registered one.
func TestBus_VocabularyNoteNamesEveryRegisteredAgent(t *testing.T) {
	b := New(3)
	b.Register("expert-001", okHandler)
	b.Register("scanner-001", okHandler)

	note := b.VocabularyNote()
	for _, want := range []string{"expert-001", "scanner-001"} {
		if !strings.Contains(note, want) {
			t.Errorf("VocabularyNote() = %q, want it to name %q", note, want)
		}
	}
	// The two endpoints agents actually invented across runs. Saying only
	// what IS legal left "fact-layer" looking plausible.
	if !strings.Contains(note, "no fact layer") {
		t.Errorf("VocabularyNote() = %q, want it to deny the endpoints agents invent", note)
	}
}

// An empty bus must render nothing, so a caller can append unconditionally
// rather than each one re-deciding — which is how the verifier came to have
// no vocabulary sentence at all.
func TestBus_VocabularyNoteIsEmptyWithNoAgents(t *testing.T) {
	if note := New(3).VocabularyNote(); note != "" {
		t.Errorf("VocabularyNote() = %q, want empty for a bus with no handlers", note)
	}
}

// A refused query must leave a trace. Before this it reached the model as one
// line of prose and produced no event at all — so "follow-up queries failed
// (agents unavailable)", the arbiter's own stated reason for capping a finding
// at needs_review, was invisible in events.jsonl across all 72 occurrences.
func TestBus_UnknownAgentEmitsFailureEvent(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-1")
	b.Register("expert-001", okHandler)

	_, err := b.AskForCase(context.Background(), "case-001", Query{
		FromAgent: "arbiter-001", ToAgent: "fact-layer", Question: "does the version propagate?",
	})
	if err == nil {
		t.Fatal("an unregistered agent must be an error")
	}

	var failures []events.Event
	for _, ev := range h.Events() {
		if ev.Type == events.TypeBusQueryFailed {
			failures = append(failures, ev)
		}
	}
	if len(failures) != 1 {
		t.Fatalf("want exactly one %s event, got %d", events.TypeBusQueryFailed, len(failures))
	}
	ev := failures[0]
	if ev.Agent != "arbiter-001" || ev.ToAgent != "fact-layer" {
		t.Errorf("event must name both ends: agent=%q to_agent=%q", ev.Agent, ev.ToAgent)
	}
	if ev.CaseID != "case-001" {
		t.Errorf("case_id = %q, want case-001", ev.CaseID)
	}
	if ev.Reason == "" {
		t.Error("reason must say why the query was refused")
	}
}

// Ask (the caseless path) refuses the same way and must record it too.
func TestBus_AskAlsoRecordsRefusal(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-1")

	if _, err := b.Ask(context.Background(), Query{FromAgent: "verifier-001", ToAgent: "nope"}); err == nil {
		t.Fatal("expected an error")
	}
	var n int
	for _, ev := range h.Events() {
		if ev.Type == events.TypeBusQueryFailed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want one failure event from Ask, got %d", n)
	}
}

// A handler that errors is also a refusal from the caller's point of view and
// must be recorded — otherwise a registered-but-broken agent is as invisible
// as an unregistered one was.
func TestBus_HandlerErrorIsRecorded(t *testing.T) {
	h := eventstest.New(t)
	b := New(3)
	b.SetRecorder(h.Recorder, "run-1")
	b.Register("expert-001", func(context.Context, Query) (Response, error) {
		return Response{}, context.DeadlineExceeded
	})

	if _, err := b.AskForCase(context.Background(), "case-001",
		Query{FromAgent: "arbiter-001", ToAgent: "expert-001"}); err == nil {
		t.Fatal("expected an error")
	}
	var n int
	for _, ev := range h.Events() {
		if ev.Type == events.TypeBusQueryFailed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want one failure event from a failing handler, got %d", n)
	}
}

// Every existing caller builds the bus with New(maxRounds) and no recorder.
// That has to keep working — a nil recorder means no events, not a panic.
func TestBus_NilRecorderIsSafe(t *testing.T) {
	b := New(3)
	if _, err := b.Ask(context.Background(), Query{FromAgent: "a", ToAgent: "nope"}); err == nil {
		t.Fatal("expected an error")
	}
}

// The dialog quota is per asking agent, not shared across the run.
//
// It used to be keyed on caseID alone, so verifier, arbiter and curator drew
// from the same three rounds. Once scanner-001 was wired up and started
// answering, the verifier spent the budget and the arbiter hit "dialog round
// limit (3) reached" before it could ask about the rollback path at all — it
// said so in its own finding.
func TestBus_QuotaIsPerAskingAgent(t *testing.T) {
	b := New(2)
	b.Register("scanner-001", okHandler)
	ask := func(from string) error {
		_, err := b.AskForCase(context.Background(), "case-001",
			Query{FromAgent: from, ToAgent: "scanner-001", Question: "?", Evidence: "e"})
		return err
	}

	// The verifier spends its whole budget.
	if err := ask("verifier-001"); err != nil {
		t.Fatalf("verifier round 1: %v", err)
	}
	if err := ask("verifier-001"); err != nil {
		t.Fatalf("verifier round 2: %v", err)
	}
	if err := ask("verifier-001"); err == nil {
		t.Fatal("verifier round 3 must exceed its own quota")
	}

	// The arbiter's is untouched.
	if err := ask("arbiter-001"); err != nil {
		t.Fatalf("the arbiter must have its own budget, got: %v", err)
	}
	if err := ask("arbiter-001"); err != nil {
		t.Fatalf("arbiter round 2: %v", err)
	}
	if err := ask("arbiter-001"); err == nil {
		t.Fatal("arbiter round 3 must exceed its own quota")
	}
}

// Different cases stay independent too.
func TestBus_QuotaIsPerCase(t *testing.T) {
	b := New(1)
	b.Register("scanner-001", okHandler)
	ask := func(caseID string) error {
		_, err := b.AskForCase(context.Background(), caseID,
			Query{FromAgent: "arbiter-001", ToAgent: "scanner-001", Question: "?", Evidence: "e"})
		return err
	}
	if err := ask("case-001"); err != nil {
		t.Fatal(err)
	}
	if err := ask("case-001"); err == nil {
		t.Fatal("second round on the same case must be refused")
	}
	if err := ask("case-002"); err != nil {
		t.Fatalf("a different case must have its own budget: %v", err)
	}
}
