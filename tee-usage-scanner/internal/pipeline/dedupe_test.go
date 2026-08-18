package pipeline_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
)

func mkCand(id string, paths, syms []string) artifacts.Candidate {
	return artifacts.Candidate{ID: id, Paths: paths, Symbols: syms}
}

func TestDedupeCandidates_NoBundlesIsEmpty(t *testing.T) {
	if got := pipeline.DedupeCandidates(nil); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestMergeEvidenceBundles_AccountsForEveryPass(t *testing.T) {
	b1 := &artifacts.EvidenceBundle{
		RunID: "run-1",
		PlannerMeta: artifacts.PlannerMeta{
			RoundsUsed: 10, RoundsBudget: 18, TokensUsed: 70000,
			WallClockMs: 1000, TerminationReason: "aggregate_token_budget",
		},
	}
	b2 := &artifacts.EvidenceBundle{
		RunID: "run-1",
		PlannerMeta: artifacts.PlannerMeta{
			RoundsUsed: 7, RoundsBudget: 18, TokensUsed: 50000,
			WallClockMs: 800, TerminationReason: "llm_done", Truncated: true,
		},
	}

	merged := pipeline.MergeEvidenceBundles([]*artifacts.EvidenceBundle{b1, b2})
	meta := merged.PlannerMeta
	if meta.RoundsUsed != 17 || meta.RoundsBudget != 36 || meta.TokensUsed != 120000 || meta.WallClockMs != 1800 {
		t.Fatalf("aggregate meta = %+v", meta)
	}
	if meta.TerminationReason != "multi_sample" || !meta.Truncated || meta.PassCount != 2 {
		t.Fatalf("multi-sample meta = %+v", meta)
	}
	if len(meta.Passes) != 2 || meta.Passes[0].TerminationReason != "aggregate_token_budget" || meta.Passes[1].TerminationReason != "llm_done" {
		t.Fatalf("pass summaries = %+v", meta.Passes)
	}
}

func TestDedupeCandidates_KeepsUniquePaths(t *testing.T) {
	b1 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("a", []string{"attest/verifier/src/dcap.rs"}, []string{"verify"}),
	}}
	b2 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("b", []string{"sgx/service/src/lib.rs"}, []string{"verify_report"}),
	}}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{b1, b2})
	if len(got) != 2 {
		t.Errorf("want 2, got %d: %v", len(got), got)
	}
}

func TestDedupeCandidates_MergesExactDuplicatesAcrossBundles(t *testing.T) {
	b1 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("a", []string{"attest/verifier/src/dcap.rs"}, []string{"verify"}),
	}}
	b2 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("a-dup", []string{"attest/verifier/src/dcap.rs"}, []string{"verify"}),
	}}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{b1, b2})
	if len(got) != 1 {
		t.Errorf("want 1 after dedup, got %d", len(got))
	}
	if got[0].ID != "a" {
		t.Errorf("expected earliest candidate to win, got %q", got[0].ID)
	}
}

func TestDedupeCandidates_KeepsDifferentSymbolsInSameFile(t *testing.T) {
	// Same file, different function → NOT duplicates
	b1 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("a", []string{"attest/verifier/src/dcap.rs"}, []string{"DcapVerifier::new"}),
	}}
	b2 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("b", []string{"attest/verifier/src/dcap.rs"}, []string{"DcapVerifier::verify"}),
	}}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{b1, b2})
	if len(got) != 2 {
		t.Errorf("want both kept, got %d: %v", len(got), got)
	}
}

func TestDedupeCandidates_OverlappingSymbolsCollide(t *testing.T) {
	b1 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("a", []string{"attest/verifier/src/dcap.rs"}, []string{"A", "B"}),
	}}
	b2 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("b", []string{"attest/verifier/src/dcap.rs"}, []string{"B", "C"}),
	}}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{b1, b2})
	if len(got) != 1 {
		t.Errorf("want 1 (overlap on B), got %d", len(got))
	}
}

func TestDedupeCandidates_PathOrderInsensitive(t *testing.T) {
	b1 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("a", []string{"a.rs", "b.rs"}, []string{"X"}),
	}}
	b2 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("b", []string{"b.rs", "a.rs"}, []string{"X"}),
	}}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{b1, b2})
	if len(got) != 1 {
		t.Errorf("want 1 (sorted-path match), got %d", len(got))
	}
}

func TestDedupeCandidates_EmptySymbolsTreatedAsWholeFile(t *testing.T) {
	// One candidate with no symbols and one with symbols on the
	// same file collide — the empty-symbols one is "whole file"
	// which supersets any specific symbol.
	b1 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("whole", []string{"a.rs"}, nil),
	}}
	b2 := &artifacts.EvidenceBundle{Candidates: []artifacts.Candidate{
		mkCand("specific", []string{"a.rs"}, []string{"foo"}),
	}}
	got := pipeline.DedupeCandidates([]*artifacts.EvidenceBundle{b1, b2})
	if len(got) != 1 {
		t.Errorf("want 1, got %d", len(got))
	}
	if got[0].ID != "whole" {
		t.Errorf("expected whole-file candidate to win, got %q", got[0].ID)
	}
}

func TestAvoidList_FormatsPathAndSymbol(t *testing.T) {
	cands := []artifacts.Candidate{
		mkCand("a", []string{"dcap.rs"}, []string{"verify"}),
		mkCand("b", []string{"lib.rs"}, []string{"A", "B"}),
		mkCand("c", []string{"nosym.rs"}, nil),
	}
	got := pipeline.AvoidList(cands)
	sort.Strings(got)
	want := []string{"dcap.rs::verify", "lib.rs::A", "lib.rs::B", "nosym.rs"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
