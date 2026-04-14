package actions_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func doneArgs(t *testing.T, summary string, candidates []map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"summary":    summary,
		"candidates": candidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDone_ValidArgs(t *testing.T) {
	cands := []map[string]any{
		{
			"id":       "candidate-001",
			"kind":     "attestation",
			"priority": "high",
			"paths":    []string{"attest/verify.rs"},
			"symbols":  []string{"verify_quote"},
			"why_selected": []string{
				"sink:attestation_verification matched",
				"reverse_trace depth 2 from verify_quote",
			},
		},
	}

	h := actions.DoneHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "done",
		Args: doneArgs(t, "audit complete, found 1 candidate", cands),
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	if !strings.Contains(result.Output, "candidate-001") {
		t.Fatalf("output missing candidate id: %s", result.Output)
	}
	if !strings.Contains(result.Output, "audit complete") {
		t.Fatalf("output missing summary: %s", result.Output)
	}
}

func TestDone_EmptyCandidatesIsAllowed(t *testing.T) {
	h := actions.DoneHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "done",
		Args: doneArgs(t, "no findings", nil),
	})
	if !result.OK {
		t.Fatalf("expected OK for empty candidates, got: %s", result.Error)
	}
}

func TestDone_InvalidJSON(t *testing.T) {
	h := actions.DoneHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "done",
		Args: json.RawMessage("not json"),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}

func TestDone_NameIsExactlyDone(t *testing.T) {
	h := actions.DoneHandler{}
	if h.Name() != "done" {
		t.Fatalf("Name() = %q, want done", h.Name())
	}
}
