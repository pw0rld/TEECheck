package arbiter

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

func TestArbitratePreservesExplicitWeaknessMetadata(t *testing.T) {
	stub := &stubLLM{responseJSON: arbiterResponseJSON}
	pack := artifacts.CasePack{CaseID: "opaque-case", RelatedTWEs: []string{"TWE-STATE-001", "TWE-GUARD-002"}}
	item, _, err := arbitrateLLM(context.Background(), stub, agentbus.New(0), pack, artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{}, caseContext{}, artifacts.ChallengerIndependentView{}, "arbiter-001", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(item)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	twes, ok := got["related_twes"].([]any)
	if !ok || len(twes) != 2 || twes[0] != "TWE-STATE-001" {
		t.Fatalf("case TWE metadata lost: %s", b)
	}
}

func TestReviewedLocationsUseValidatedCitationsOnly(t *testing.T) {
	valid := citations.CitedBytes{File: "ta/verify.c", StartLine: 42, EndLine: 43, StartByte: 100, EndByte: 150, SHA256: "resolved-hash"}
	stale := valid
	stale.StartLine = 90
	unanchored := valid
	unanchored.SHA256 = ""
	memo := artifacts.VerificationMemo{
		ConfirmedCitedFacts:      []citations.CitedFact{{Cited: []citations.CitedBytes{valid, unanchored}}},
		ExpertCitationValidation: []citations.CitationValidation{{Status: citations.StatusStale, Cited: []citations.CitedBytes{stale}}, {Status: citations.StatusValid, Cited: []citations.CitedBytes{valid}}},
	}
	got := reviewedFindingLocations(caseContext{}, memo)
	if len(got) != 1 || got[0].Path != "ta/verify.c" || got[0].StartLine != 42 {
		t.Fatalf("validated locations=%+v", got)
	}
}
