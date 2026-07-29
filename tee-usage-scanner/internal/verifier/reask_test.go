package verifier

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

const arrayWrappedVerifier = `[["status"], {"status": "contested", "queries": []}]`

const cleanVerifier = `{"status": "corroborated", "notes": ["recovered on the re-ask"], "queries": []}`

func TestBuildMemoLLM_SurvivesOneMalformedReply(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedVerifier, cleanVerifier}}
	pack := artifacts.CasePack{CaseID: "case-001"}

	memo, err := buildMemoLLM(context.Background(), fake, agentbus.New(0), t.TempDir(), pack,
		artifacts.Hypothesis{}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil)
	if err != nil {
		t.Fatalf("buildMemoLLM: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (reply + one corrective re-ask)", len(fake.Calls))
	}
	if memo.Status != "corroborated" || len(memo.Notes) != 1 || memo.Notes[0] != "recovered on the re-ask" {
		t.Fatalf("memo = %+v, want the re-asked reply's fields", memo)
	}
}

func TestBuildMemoLLM_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedVerifier, `["still an array"]`}, Default: cleanVerifier}

	if _, err := buildMemoLLM(context.Background(), fake, agentbus.New(0), t.TempDir(), artifacts.CasePack{CaseID: "case-001"},
		artifacts.Hypothesis{}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil); err == nil {
		t.Fatal("want an error after two malformed replies")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2", len(fake.Calls))
	}
}
