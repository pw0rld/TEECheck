package challenger

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

// The literal reply that killed the live glm-5.2 run: phase-1's object,
// wrapped in an array. The reasoning inside it was correct and specific, and
// the whole pipeline died on the wrapper.
const arrayWrappedPhase1 = `[["hash_idx"], {"issue_present": true, "reasoning": "hash_is_valid(hash_idx) at lines 58-63 is inside the guarded branch", "confidence": "high"}]`

const cleanPhase1 = `{"issue_present": true, "reasoning": "recovered on the re-ask", "confidence": "high"}`

// offVocabPhase1 parses fine but its rating is off-vocabulary — the SECOND,
// distinct check that generateWithRatingRetry owns.
const offVocabPhase1 = `{"issue_present": true, "reasoning": "recovered on the re-ask", "confidence": "very sure"}`

func TestBuildIndependentViewLLM_SurvivesOneMalformedReply(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedPhase1, cleanPhase1}}
	pack := artifacts.CasePack{CaseID: "case-001", Category: "rollback"}

	view, adjustments, err := buildIndependentViewLLM(context.Background(), fake, stubToolAdapter{}, t.TempDir(), pack, caseContext{}, "challenger-001", 0)
	if err != nil {
		t.Fatalf("buildIndependentViewLLM: %v", err)
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want 2 (reply + one corrective parse re-ask)", len(fake.Calls))
	}
	if view.Reasoning != "recovered on the re-ask" {
		t.Fatalf("reasoning = %q, want the re-asked reply's reasoning", view.Reasoning)
	}
	if view.Confidence != "high" {
		t.Errorf("confidence = %q, want high", view.Confidence)
	}
	if len(adjustments) != 0 {
		t.Errorf("adjustments = %+v, want none (the rating was legal; only the envelope was malformed)", adjustments)
	}
}

// The two re-asks are distinct checks and they nest: the parse re-ask sits
// underneath each rating attempt. Four calls is the ceiling for one phase —
// two rating attempts, each of which may itself be re-asked once for shape.
func TestBuildIndependentViewLLM_ParseAndRatingReAsksBoundAtFourCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{
		arrayWrappedPhase1, // attempt 1: malformed envelope
		offVocabPhase1,     // attempt 1 re-ask: parses, rating off-vocabulary
		arrayWrappedPhase1, // attempt 2 (rating re-ask): malformed envelope again
		cleanPhase1,        // attempt 2 re-ask: parses, rating legal
	}, Default: cleanPhase1}
	pack := artifacts.CasePack{CaseID: "case-001"}

	view, adjustments, err := buildIndependentViewLLM(context.Background(), fake, stubToolAdapter{}, t.TempDir(), pack, caseContext{}, "challenger-001", 0)
	if err != nil {
		t.Fatalf("buildIndependentViewLLM: %v", err)
	}
	if len(fake.Calls) != 4 {
		t.Fatalf("llm calls = %d, want exactly 4 (2 rating attempts x at most 2 shape attempts)", len(fake.Calls))
	}
	if view.Confidence != "high" {
		t.Errorf("confidence = %q, want the recovered high", view.Confidence)
	}
	if len(adjustments) != 1 || adjustments[0].Kind != "reask_recovered" {
		t.Fatalf("adjustments = %+v, want one reask_recovered", adjustments)
	}
}

// Exhausting both re-asks on both attempts still stops at four calls, and
// still yields an unrated field rather than another agent's judgement.
func TestBuildIndependentViewLLM_NeverExceedsFourCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{
		arrayWrappedPhase1, offVocabPhase1, arrayWrappedPhase1, `["still an array"]`,
	}, Default: cleanPhase1}

	view, adjustments, err := buildIndependentViewLLM(context.Background(), fake, stubToolAdapter{}, t.TempDir(),
		artifacts.CasePack{CaseID: "case-001"}, caseContext{}, "challenger-001", 0)
	if err != nil {
		t.Fatalf("buildIndependentViewLLM: %v", err)
	}
	if len(fake.Calls) != 4 {
		t.Fatalf("llm calls = %d, want exactly 4", len(fake.Calls))
	}
	if view.Confidence != artifacts.RatingUnrated {
		t.Errorf("confidence = %q, want %q", view.Confidence, artifacts.RatingUnrated)
	}
	if len(adjustments) != 1 || adjustments[0].Kind != "unrated_fallback" {
		t.Fatalf("adjustments = %+v, want one unrated_fallback", adjustments)
	}
}

// Two malformed replies on the FIRST attempt is a real failure: the phase
// errors out after exactly two calls, without spending the rating budget on
// a model that cannot produce an object.
func TestBuildIndependentViewLLM_TwoMalformedRepliesFailAfterExactlyTwoCalls(t *testing.T) {
	fake := &llmtest.FakeClient{Responses: []string{arrayWrappedPhase1, `["still an array"]`}, Default: cleanPhase1}

	if _, _, err := buildIndependentViewLLM(context.Background(), fake, stubToolAdapter{}, t.TempDir(),
		artifacts.CasePack{CaseID: "case-001"}, caseContext{}, "challenger-001", 0); err == nil {
		t.Fatal("want an error after two malformed replies")
	}
	if len(fake.Calls) != 2 {
		t.Fatalf("llm calls = %d, want exactly 2", len(fake.Calls))
	}
}
