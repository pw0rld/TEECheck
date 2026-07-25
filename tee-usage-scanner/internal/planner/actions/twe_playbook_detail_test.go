package actions

import (
	"context"
	"strings"
	"testing"
)

type fakeDetailSource struct {
	byID  map[string]string
	calls []string
}

func (f *fakeDetailSource) Detail(tweID string) (string, bool) {
	f.calls = append(f.calls, tweID)
	text, ok := f.byID[tweID]
	return text, ok
}

func TestTWEPlaybookDetail_ReturnsFullText(t *testing.T) {
	src := &fakeDetailSource{byID: map[string]string{
		"TWE-STATE-001": "[TWE-STATE-001] Trusted State Rollback\nInvestigate: step_one\nFalse positives: fp_one\n",
	}}
	h := &TWEPlaybookDetailHandler{Source: src}
	res := h.Run(context.Background(), ActionRequest{Args: []byte(`{"twe_id":"TWE-STATE-001"}`)})
	if !res.OK {
		t.Fatalf("expected OK, got error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "False positives:") {
		t.Errorf("expected the detail-tier text, got:\n%s", res.Output)
	}
	if len(src.calls) != 1 || src.calls[0] != "TWE-STATE-001" {
		t.Errorf("expected one lookup for TWE-STATE-001, got %v", src.calls)
	}
}

// An unknown id must be an explicit error, never an empty success — an agent
// must not read "no text" as "this weakness does not apply".
func TestTWEPlaybookDetail_UnknownIDIsAnError(t *testing.T) {
	h := &TWEPlaybookDetailHandler{Source: &fakeDetailSource{byID: map[string]string{}}}
	res := h.Run(context.Background(), ActionRequest{Args: []byte(`{"twe_id":"TWE-NOPE-999"}`)})
	if res.OK {
		t.Fatal("expected OK=false for an unknown TWE id")
	}
	if res.Error == "" {
		t.Error("expected a non-empty Error explaining the miss")
	}
}

func TestTWEPlaybookDetail_RejectsBadArgs(t *testing.T) {
	h := &TWEPlaybookDetailHandler{Source: &fakeDetailSource{byID: map[string]string{}}}
	if res := h.Run(context.Background(), ActionRequest{Args: []byte(`{}`)}); res.OK {
		t.Error("expected OK=false when twe_id is missing")
	}
	if res := h.Run(context.Background(), ActionRequest{Args: []byte(`not json`)}); res.OK {
		t.Error("expected OK=false for malformed args")
	}
}

// The catalog can legitimately be absent (a knowledge root with no playbook
// directory); the action must fail per call rather than panic.
func TestTWEPlaybookDetail_NilSourceFailsClosed(t *testing.T) {
	h := &TWEPlaybookDetailHandler{}
	res := h.Run(context.Background(), ActionRequest{Args: []byte(`{"twe_id":"TWE-STATE-001"}`)})
	if res.OK || res.Error == "" {
		t.Error("expected a per-call failure when no catalog is loaded")
	}
}

func TestTWEPlaybookDetail_Name(t *testing.T) {
	if got := (&TWEPlaybookDetailHandler{}).Name(); got != "twe_playbook_detail" {
		t.Errorf("Name() = %q", got)
	}
}
