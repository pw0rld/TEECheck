package pipeline

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// A prefetched ToolFact has to reach a Case Pack, because CasePack.ToolFactRefs
// is what expert/challenger/verifier/arbiter actually read.
//
// Attaching it to the investigation alone is not enough: an investigation that
// located no roles produces a pack with no target files, and DedupePacks drops
// those on purpose. On 2026-07-31 the vulnerable side collected the correct
// ToolFact, both investigations carried the ref, both investigation-derived
// packs were dropped for having no targets, and the surviving candidate-derived
// pack carried nothing.
func TestAttachPrefetchedFacts_MatchesOnLocationPath(t *testing.T) {
	packs := []artifacts.CasePack{
		{CaseID: "a", TargetFiles: []string{"core/crypto/signed_hdr.c"}},
		{CaseID: "b", TargetFiles: []string{"core/kernel/other.c"}},
	}
	got := attachPrefetchedFacts(packs, []prefetchedFact{
		{Ref: "/runs/x/fact.json", Paths: []string{"core/crypto/signed_hdr.c"}},
	})
	if len(got[0].ToolFactRefs) != 1 {
		t.Errorf("the pack targeting the flagged file must carry the fact: %v", got[0].ToolFactRefs)
	}
	if len(got[1].ToolFactRefs) != 0 {
		t.Errorf("a pack about an unrelated file must not: %v", got[1].ToolFactRefs)
	}
}

// A query that matched nothing is a statement about the whole tree at this
// commit, not about one file — it has no location to intersect. Every pack
// gets it, because "we ran this and found nothing anywhere" is evidence for
// any case in the run.
func TestAttachPrefetchedFacts_ZeroLocationFactGoesToEveryPack(t *testing.T) {
	packs := []artifacts.CasePack{
		{CaseID: "a", TargetFiles: []string{"core/crypto/signed_hdr.c"}},
		{CaseID: "b", TargetFiles: []string{"core/kernel/other.c"}},
	}
	got := attachPrefetchedFacts(packs, []prefetchedFact{{Ref: "/runs/x/clean.json"}})
	for _, p := range got {
		if len(p.ToolFactRefs) != 1 {
			t.Errorf("pack %s must carry the repo-wide negative: %v", p.CaseID, p.ToolFactRefs)
		}
	}
}

// A ref the pack already has must not be duplicated.
func TestAttachPrefetchedFacts_NoDuplicates(t *testing.T) {
	packs := []artifacts.CasePack{{
		CaseID: "a", TargetFiles: []string{"f.c"}, ToolFactRefs: []string{"/runs/x/fact.json"},
	}}
	got := attachPrefetchedFacts(packs, []prefetchedFact{
		{Ref: "/runs/x/fact.json", Paths: []string{"f.c"}},
	})
	if len(got[0].ToolFactRefs) != 1 {
		t.Fatalf("ToolFactRefs = %v, want one", got[0].ToolFactRefs)
	}
}

// Nothing prefetched changes nothing.
func TestAttachPrefetchedFacts_NoFactsIsIdentity(t *testing.T) {
	packs := []artifacts.CasePack{{CaseID: "a", TargetFiles: []string{"f.c"}}}
	if got := attachPrefetchedFacts(packs, nil); len(got[0].ToolFactRefs) != 0 {
		t.Fatalf("ToolFactRefs = %v, want none", got[0].ToolFactRefs)
	}
}
