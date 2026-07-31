package arbiter

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

const arrayWrappedArbiter = `[["status"], {"status": "needs_review", "summary": "rejected", "queries": []}]`

const cleanArbiter = `{"status": "needs_review", "severity": "medium", "confidence": "low", "summary": "recovered on the re-ask", "queries": []}`

func TestArbitrateLLM_SurvivesOneMalformedReply(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedArbiter, cleanArbiter}}

	item, _, err := arbitrateLLM(context.Background(), fake, agentbus.New(0), artifacts.CasePack{CaseID: "case-001"},
		artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{},
		caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0)
	if err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (reply + one corrective re-ask)", len(fake.Calls))
	}
	if item.Summary != "recovered on the re-ask" {
		t.Fatalf("summary = %q, want the re-asked reply's summary", item.Summary)
	}
}

func TestArbitrateLLM_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedArbiter, `["still an array"]`}, Default: cleanArbiter}

	if _, _, err := arbitrateLLM(context.Background(), fake, agentbus.New(0), artifacts.CasePack{CaseID: "case-001"},
		artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{},
		caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0); err == nil {
		t.Fatal("want an error after two malformed replies")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2", len(fake.Calls))
	}
}
