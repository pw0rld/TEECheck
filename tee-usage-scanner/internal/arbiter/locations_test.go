package arbiter

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// rollbackFact is the ToolFact run 44362-vuln-p9 actually produced: one
// primary location, and a finding naming the producer and both call sites of
// the rollback authority in a different file.
func rollbackFact() artifacts.ToolFact {
	return artifacts.ToolFact{
		FactID:    "trustir-cpp-cpp.state.rollback_version_propagation-39aac16b6e84fd57",
		Tool:      "trustir-cpp",
		Operation: "cpp.state.rollback_version_propagation",
		Status:    "success",
		Locations: []artifacts.ToolLocation{{Path: "core/crypto/signed_hdr.c", StartLine: 262}},
		Findings: []artifacts.ToolFinding{{
			Message:  "TWE-STATE-001: producer never propagates rollback field 'version'",
			Location: artifacts.ToolLocation{Path: "core/crypto/signed_hdr.c", StartLine: 262},
			Related: []artifacts.ToolLocation{
				{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
				{Path: "core/kernel/ree_fs_ta.c", StartLine: 639, Symbol: "check_update_version"},
				{Path: "core/kernel/ree_fs_ta.c", StartLine: 314, Symbol: "check_update_version"},
			},
		}},
	}
}

// The benchmark scorer matches on line. Every finding this package emitted
// carried Files (paths only) and no Locations at all, while the ToolFact in
// the same case named the exact line — p9's finding said
// core/crypto/signed_hdr.c and the fact said :262.
func TestFindingLocations_ComeFromTheToolFact(t *testing.T) {
	got := findingLocations(caseContext{toolFacts: []artifacts.ToolFact{rollbackFact()}})

	want := []artifacts.FindingLocation{
		{Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
		{Path: "core/kernel/ree_fs_ta.c", StartLine: 314, Symbol: "check_update_version"},
		{Path: "core/kernel/ree_fs_ta.c", StartLine: 639, Symbol: "check_update_version"},
	}
	if len(got) != len(want) {
		t.Fatalf("locations = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("locations = %+v, want %+v (sorted, deduped)", got, want)
		}
	}
}

// A query that ran and matched nothing must yield no locations — that is the
// fixed half of a differential, and inventing a location there would make the
// two revisions look alike.
func TestFindingLocations_ZeroMatchYieldsNone(t *testing.T) {
	fact := artifacts.ToolFact{Status: "success", Operation: "cpp.state.rollback_version_propagation"}
	if got := findingLocations(caseContext{toolFacts: []artifacts.ToolFact{fact}}); len(got) != 0 {
		t.Fatalf("locations = %+v, want none for a fact that matched nothing", got)
	}
}

// A location with no line is not a location. An unresolved fact carries paths
// with StartLine 0; emitting those would point the scorer at line 0.
func TestFindingLocations_SkipsIncompletePositions(t *testing.T) {
	fact := artifacts.ToolFact{
		Status:    "success",
		Locations: []artifacts.ToolLocation{{Path: "a.c", StartLine: 0}, {Path: "", StartLine: 12}},
	}
	if got := findingLocations(caseContext{toolFacts: []artifacts.ToolFact{fact}}); len(got) != 0 {
		t.Fatalf("locations = %+v, want none — neither entry is a usable position", got)
	}
}

// And it has to reach the emitted finding, not just exist as a function.
func TestArbitrateLLM_FindingCarriesToolFactLocations(t *testing.T) {
	stub := &stubLLM{responseJSON: arbiterResponseJSON}

	item, _, err := arbitrateLLM(context.Background(), stub, agentbus.New(0),
		artifacts.CasePack{CaseID: "case-001", TargetFiles: []string{"core/crypto/signed_hdr.c"}},
		artifacts.Hypothesis{}, artifacts.Challenge{}, artifacts.VerificationMemo{},
		caseContext{toolFacts: []artifacts.ToolFact{rollbackFact()}},
		artifacts.ChallengerIndependentView{}, "arbiter-001", 0)
	if err != nil {
		t.Fatalf("arbitrateLLM: %v", err)
	}
	if len(item.Locations) != 3 {
		t.Fatalf("finding Locations = %+v, want the three ToolFact positions", item.Locations)
	}
	if item.Locations[0].StartLine != 262 {
		t.Errorf("first location = %+v, want signed_hdr.c:262", item.Locations[0])
	}
}
