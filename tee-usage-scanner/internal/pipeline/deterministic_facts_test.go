package pipeline

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// TestFactCasePack_GroundsLocationsAndToolFactRef checks the P4+ promotion
// shape: a positive fact-layer result becomes a CasePack that carries the
// finding's files/symbols, references the persisted ToolFact (not a copy),
// and tags the TWE whose playbook the Challenger must load.
func TestFactCasePack_GroundsLocationsAndToolFactRef(t *testing.T) {
	fact := artifacts.ToolFact{
		FactID: "trustir-cpp-cpp.state.rollback_version_propagation-deadbeef",
		Status: trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{
			{Path: "core/crypto/signed_hdr.c", StartLine: 317, EndLine: 317},
		},
		Findings: []artifacts.ToolFinding{
			{
				Message: "producer shdr_load_pub_key never propagates rollback field 'version'",
				Related: []artifacts.ToolLocation{
					{Path: "core/kernel/ree_fs_ta.c", Symbol: "check_update_version"},
					{Path: "core/crypto/signed_hdr.c", Symbol: "shdr_load_pub_key"},
				},
			},
		},
	}
	pack := factCasePack(fact, "02_tool_facts/trustir/facts/foo.json",
		trustirfacts.OperationRollbackVersionPropagation, "tee", nil)

	if pack.SchemaVersion != "teecheck.case_pack.v1" {
		t.Errorf("SchemaVersion = %q, want teecheck.case_pack.v1", pack.SchemaVersion)
	}
	if pack.Priority != "high" {
		t.Errorf("Priority = %q, want high (tool-confirmed)", pack.Priority)
	}
	if len(pack.TargetFiles) != 1 || pack.TargetFiles[0] != "core/crypto/signed_hdr.c" {
		t.Errorf("TargetFiles = %v, want [core/crypto/signed_hdr.c]", pack.TargetFiles)
	}
	if len(pack.TargetSymbols) != 2 {
		t.Errorf("TargetSymbols = %v, want the 2 named sites", pack.TargetSymbols)
	}
	// ToolFact travels by reference, not value.
	if len(pack.ToolFactRefs) != 1 || pack.ToolFactRefs[0] != "02_tool_facts/trustir/facts/foo.json" {
		t.Errorf("ToolFactRefs = %v", pack.ToolFactRefs)
	}
	if len(pack.RelatedTWEs) != 1 || pack.RelatedTWEs[0] != "TWE-STATE-001" {
		t.Errorf("RelatedTWEs = %v, want [TWE-STATE-001]", pack.RelatedTWEs)
	}
	if !strings.Contains(pack.WhySelected[0], "never propagates") {
		t.Errorf("WhySelected should carry the query's own conclusion, got %q", pack.WhySelected[0])
	}
	if !strings.HasPrefix(pack.CaseID, "deterministic:") {
		t.Errorf("CaseID = %q, want deterministic: prefix", pack.CaseID)
	}
}

// TestFactCasePack_FallsBackWhenNoMessage ensures a location-only result (no
// finding message) still produces a reviewable pack with a provenance line.
func TestFactCasePack_FallsBackWhenNoMessage(t *testing.T) {
	fact := artifacts.ToolFact{
		FactID:    "trustir-cpp-cpp.state.rollback_version_propagation-cafebabe",
		Status:    trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{{Path: "a.c", StartLine: 1}},
	}
	pack := factCasePack(fact, "f.json", trustirfacts.OperationRollbackVersionPropagation, "tee", nil)
	if len(pack.TargetFiles) != 1 || pack.TargetFiles[0] != "a.c" {
		t.Errorf("TargetFiles = %v", pack.TargetFiles)
	}
	if !strings.Contains(pack.WhySelected[0], "structural positive") {
		t.Errorf("fallback WhySelected should name the lane, got %q", pack.WhySelected[0])
	}
}

// TestCapPreservingGrounded_KeepsGroundedWhenLast is the property that matters:
// a tool-grounded pack must survive the cap even when it is the last pack and a
// naive [:max] would drop it.
func TestCapPreservingGrounded_KeepsGroundedWhenLast(t *testing.T) {
	grounded := artifacts.CasePack{CaseID: "g", TargetFiles: []string{"z.c"}, ToolFactRefs: []string{"fact.json"}}
	leads := make([]artifacts.CasePack, 5)
	for i := range leads {
		leads[i] = artifacts.CasePack{CaseID: "lead", TargetFiles: []string{string(rune('a'+i)) + ".c"}}
	}
	// Grounded first: a naive cap keeps it by luck.
	gotFirst := capPreservingGrounded(append([]artifacts.CasePack{grounded}, leads...), 3)
	if len(gotFirst) != 3 {
		t.Fatalf("len = %d, want 3", len(gotFirst))
	}
	// Grounded last: the cap must still keep it.
	gotLast := capPreservingGrounded(append(append([]artifacts.CasePack{}, leads...), grounded), 3)
	if len(gotLast) != 3 {
		t.Fatalf("len = %d, want 3", len(gotLast))
	}
	survived := false
	for _, p := range gotLast {
		if p.CaseID == "g" {
			survived = true
		}
	}
	if !survived {
		t.Errorf("grounded pack was truncated when last; cap must preserve tool-grounded packs: %+v", gotLast)
	}
}

func TestCapPreservingGrounded_NoOpUnderLimit(t *testing.T) {
	packs := []artifacts.CasePack{{CaseID: "a", TargetFiles: []string{"a.c"}}}
	if got := capPreservingGrounded(packs, 8); len(got) != 1 {
		t.Errorf("under limit: expected unchanged, got %d", len(got))
	}
	if got := capPreservingGrounded(packs, 0); len(got) != 1 {
		t.Errorf("max<=0 means no cap, got %d", len(got))
	}
}

// TestFactCasePack_SetsStructuralMissingLinks is the codex-R2 HIGH fix: a
// structural-only deterministic CasePack must carry a non-empty MissingLinks
// naming the producer→authority dataflow the query does NOT trace, so the
// arbiter's attackChainComplete gate returns false and the finding is labeled
// likely_issue (still surfaced) rather than overclaimed confirmed_candidate
// from flow-empty evidence. It also carries CoverageGaps and RequiredEvidence
// for complete evidential semantics.
func TestFactCasePack_SetsStructuralMissingLinks(t *testing.T) {
	fact := artifacts.ToolFact{
		FactID: "trustir-cpp-cpp.state.rollback_version_propagation-deadbeef",
		Status: trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{
			{Path: "core/crypto/signed_hdr.c", StartLine: 317},
		},
		Findings: []artifacts.ToolFinding{
			{
				Message: "producer shdr_load_pub_key never propagates rollback field 'version'",
				Related: []artifacts.ToolLocation{
					{Path: "core/crypto/signed_hdr.c", Symbol: "shdr_load_pub_key"},
					{Path: "core/kernel/ree_fs_ta.c", Symbol: "check_update_version"},
				},
			},
		},
	}
	pack := factCasePack(fact, "f.json", trustirfacts.OperationRollbackVersionPropagation, "tee", nil)

	if len(pack.MissingLinks) == 0 {
		t.Fatalf("MissingLinks empty; structural-only pack must name the untraced dataflow so the gate is honest")
	}
	link := pack.MissingLinks[0]
	if !strings.Contains(link, "shdr_load_pub_key") || !strings.Contains(link, "check_update_version") {
		t.Errorf("MissingLinks should name both producer and authority, got %q", link)
	}
	if !strings.Contains(link, "not mechanically traced") {
		t.Errorf("MissingLinks should state the dataflow is not mechanically traced, got %q", link)
	}
	if len(pack.CoverageGaps) == 0 {
		t.Errorf("CoverageGaps empty; should disclose the structural-only scope")
	}
	if len(pack.RequiredEvidence) == 0 {
		t.Errorf("RequiredEvidence empty; should state what would resolve the link")
	}
}

// TestFactCasePack_MissingLinksFallbackNoSymbols ensures a location-only result
// (no named Related symbols) still sets a generic structural MissingLinks — the
// gate must be honest regardless of whether the query named specific sites.
func TestFactCasePack_MissingLinksFallbackNoSymbols(t *testing.T) {
	fact := artifacts.ToolFact{
		FactID:    "trustir-cpp-cpp.state.rollback_version_propagation-cafebabe",
		Status:    trustirfacts.StatusSuccess,
		Locations: []artifacts.ToolLocation{{Path: "a.c", StartLine: 1}},
	}
	pack := factCasePack(fact, "f.json", trustirfacts.OperationRollbackVersionPropagation, "tee", nil)
	if len(pack.MissingLinks) != 1 {
		t.Fatalf("MissingLinks = %v, want exactly one generic entry", pack.MissingLinks)
	}
	if strings.Contains(pack.MissingLinks[0], "shdr_load_pub_key") {
		t.Errorf("fallback MissingLinks should not name a specific symbol, got %q", pack.MissingLinks[0])
	}
	if !strings.Contains(pack.MissingLinks[0], "not mechanically traced") {
		t.Errorf("fallback MissingLinks should still state the structural-only caveat, got %q", pack.MissingLinks[0])
	}
}

// TestProducerAuthoritySymbols covers the document-order, distinct-symbol
// extraction and its ok=false fallback.
func TestProducerAuthoritySymbols(t *testing.T) {
	twoSite := artifacts.ToolFact{Findings: []artifacts.ToolFinding{{Related: []artifacts.ToolLocation{
		{Symbol: "producer_fn"},
		{Symbol: "authority_fn"},
	}}}}
	if p, a, ok := producerAuthoritySymbols(twoSite); !ok || p != "producer_fn" || a != "authority_fn" {
		t.Errorf("two-site = (%q,%q,%t), want (producer_fn,authority_fn,true)", p, a, ok)
	}
	oneSite := artifacts.ToolFact{Findings: []artifacts.ToolFinding{{Related: []artifacts.ToolLocation{
		{Symbol: "only_fn"},
	}}}}
	if _, _, ok := producerAuthoritySymbols(oneSite); ok {
		t.Errorf("one-site should return ok=false")
	}
	none := artifacts.ToolFact{Findings: []artifacts.ToolFinding{{Related: []artifacts.ToolLocation{
		{Symbol: "x"}, {Symbol: "x"}, // duplicates of one symbol
	}}}}
	if _, _, ok := producerAuthoritySymbols(none); ok {
		t.Errorf("duplicate-single-symbol should return ok=false (needs two distinct)")
	}
}
