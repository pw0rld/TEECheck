package investigations_test

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/investigations"
	"testing"
)

func TestInvestigation_DistinctPropertyContractsHaveDistinctIDs(t *testing.T) {
	c := artifacts.CaseInvariantV2{Origin: "planner", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, RequiredProperty: artifacts.ContractProperty{Kind: "field_propagation", TargetFields: []string{"key.version"}}}
	wire := investigations.WireInvestigation{CaseInvariants: []artifacts.CaseInvariantV2{c}}
	a := investigations.Build(wire)
	wire.CaseInvariants[0].RequiredProperty.Kind = "guard_dominance"
	b := investigations.Build(wire)
	if a.InvestigationID == b.InvestigationID {
		t.Fatal("distinct properties collide on persisted investigation ID")
	}
	pack := investigations.BuildCasePack(a, investigations.CasePackInput{CaseID: a.InvestigationID})
	if len(pack.CaseInvariants) != 1 || pack.CaseInvariants[0].RequiredProperty.Kind != "field_propagation" {
		t.Fatal("case contract lost or aliased")
	}
}
