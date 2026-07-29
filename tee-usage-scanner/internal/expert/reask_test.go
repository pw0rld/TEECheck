package expert

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

const arrayWrappedExpert = `[["title"], {"title": "rejected", "summary": "s", "confidence": "medium"}]`

const cleanExpert = `{"title": "recovered on the re-ask", "summary": "s", "suspected_issue": "i", "confidence": "medium"}`

func TestBuildHypothesisLLM_SurvivesOneMalformedReply(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedExpert, cleanExpert}}
	pack := artifacts.CasePack{CaseID: "case-001", Category: "authorization", Priority: "high"}

	h, err := buildHypothesisLLM(context.Background(), fake, stubToolAdapter{}, t.TempDir(), pack, caseContext{}, "expert-001", 0)
	if err != nil {
		t.Fatalf("buildHypothesisLLM: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (reply + one corrective re-ask)", len(fake.Calls))
	}
	if h.Title != "recovered on the re-ask" {
		t.Fatalf("title = %q, want the re-asked reply's title", h.Title)
	}
}

func TestBuildHypothesisLLM_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedExpert, `["still an array"]`}, Default: cleanExpert}
	pack := artifacts.CasePack{CaseID: "case-001"}

	if _, err := buildHypothesisLLM(context.Background(), fake, stubToolAdapter{}, t.TempDir(), pack, caseContext{}, "expert-001", 0); err == nil {
		t.Fatal("want an error after two malformed replies")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2", len(fake.Calls))
	}
}
