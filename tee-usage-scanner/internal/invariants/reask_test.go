package invariants

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

const arrayWrappedInvariants = `[["invariants"], {"invariants": [{"invariant_id": "INV-STATE-001", "statement": "s"}]}]`

const cleanInvariants = `{"invariants": [{"invariant_id": "INV-STATE-002", "statement": "recovered on the re-ask"}]}`

func TestBuildLLM_SurvivesOneMalformedReply(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedInvariants, cleanInvariants}}

	got, err := BuildLLM(context.Background(), fake, Input{TWEContext: "TWE-STATE-001"}, 0.2)
	if err != nil {
		t.Fatalf("BuildLLM: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (reply + one corrective re-ask)", len(fake.Calls))
	}
	if len(got) != 1 || got[0].InvariantID != "INV-STATE-002" {
		t.Fatalf("invariants = %+v, want the re-asked reply's invariant", got)
	}
}

func TestBuildLLM_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedInvariants, `["still an array"]`}, Default: cleanInvariants}

	if _, err := BuildLLM(context.Background(), fake, Input{}, 0.2); err == nil {
		t.Fatal("want an error after two malformed replies")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2", len(fake.Calls))
	}
}
