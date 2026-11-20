package pipeline_test

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"testing"
)

func TestDedupeCandidatesSubsetMergesEvidence(t *testing.T) {
	a := artifacts.Candidate{ID: "a", Kind: "attestation", Paths: []string{"main.c"}, Symbols: []string{"verify"}, WhySelected: []string{"first"}, EvidenceRefs: []string{"first.json"}, Priority: "low"}
	b := artifacts.Candidate{ID: "b", Kind: "attestation", Paths: []string{"main.c", "helper.c"}, Symbols: []string{"verify"}, WhySelected: []string{"second"}, EvidenceRefs: []string{"second.json"}, Priority: "high"}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{{Candidates: []artifacts.Candidate{a, b}}})
	if len(got) != 1 {
		t.Fatalf("same site not deduplicated: %+v", got)
	}
	c := got[0]
	if c.ID != "a" || len(c.Paths) != 2 || len(c.WhySelected) != 2 || len(c.EvidenceRefs) != 2 || c.Priority != "high" {
		t.Fatalf("duplicate evidence dropped: %+v", c)
	}
}

func TestDedupeCandidatesKeepsDifferentKindsWithoutSymbols(t *testing.T) {
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{{Candidates: []artifacts.Candidate{
		{Kind: "attestation", Paths: []string{"main.c"}}, {Kind: "key_management", Paths: []string{"main.c"}},
	}}})
	if len(got) != 2 {
		t.Fatalf("distinct issues collapsed: %+v", got)
	}
}
