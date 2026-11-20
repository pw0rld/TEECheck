package planner

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"testing"
)

func TestDedupe_PreservesDistinctPropertyContractsOnSameFunction(t *testing.T) {
	base := artifacts.CasePack{CaseID: "a", TargetFiles: []string{"a.c"}, TargetSymbols: []string{"load"}, CaseInvariants: []artifacts.CaseInvariantV2{{Origin: "planner", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, RequiredProperty: artifacts.ContractProperty{Kind: "field_propagation", TargetFields: []string{"key.version"}}}}}
	other := base
	other.CaseID = "b"
	other.CaseInvariants = []artifacts.CaseInvariantV2{{Origin: "deterministic", Subjects: base.CaseInvariants[0].Subjects, RequiredProperty: artifacts.ContractProperty{Kind: "guard_dominance", TargetFields: []string{"key.modulus"}}}}
	if got := DedupePacks([]artifacts.CasePack{base, other}); len(got) != 2 {
		t.Fatalf("distinct property collapsed: %+v", got)
	}
	other.CaseInvariants = append([]artifacts.CaseInvariantV2(nil), base.CaseInvariants...)
	other.CaseInvariants[0].Origin = "deterministic"
	got := DedupePacks([]artifacts.CasePack{base, other})
	if len(got) != 1 || len(got[0].CaseInvariants) != 1 || got[0].CaseInvariants[0].Origin != "both" {
		t.Fatalf("duplicate origins not combined: %+v", got)
	}
}
