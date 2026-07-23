package investigations_test

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/investigations"
)

// TestBuildCasePack_CarriesEveryAdditiveField exercises §24's exact list:
// related TWE IDs, related invariant IDs, architecture slice refs, ToolFact
// refs, required evidence, missing links, common defenses/false positives,
// coverage gaps.
func TestBuildCasePack_CarriesEveryAdditiveField(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs:           []string{"TWE-STATE-001"},
		InvariantIDs:     []string{"INV-STATE-001"},
		ArchitectureRefs: []string{"comp:loader"},
		ToolFactRefs:     []string{"/run/02_tool_facts/trustir/fact-1.json"},
		RequiredEvidence: []string{"reachable_restore_or_load_path"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer": {Path: "core/crypto/signed_hdr.c", StartLine: 262, Symbol: "shdr_load_pub_key"},
		},
		MissingRoles: []string{"rollback_authority"},
	})

	pack := investigations.BuildCasePack(inv, investigations.CasePackInput{
		CaseID:               "case-001",
		Focus:                "op-tee rollback",
		Priority:             "high",
		CommonDefenses:       []string{"correctly_propagated_signed_version_to_rollback_database"},
		CommonFalsePositives: []string{"restored_state_is_only_a_non_security_cache"},
	})

	if pack.CaseID != "case-001" || pack.Focus != "op-tee rollback" {
		t.Errorf("identity fields not carried: %+v", pack)
	}
	if pack.Category != investigations.ClassificationStandard {
		t.Errorf("Category = %q, want the investigation's classification", pack.Category)
	}
	if len(pack.RelatedTWEs) != 1 || pack.RelatedTWEs[0] != "TWE-STATE-001" {
		t.Errorf("RelatedTWEs = %v", pack.RelatedTWEs)
	}
	if len(pack.RelatedInvariants) != 1 || pack.RelatedInvariants[0] != "INV-STATE-001" {
		t.Errorf("RelatedInvariants = %v", pack.RelatedInvariants)
	}
	if len(pack.ArchitectureRefs) != 1 || pack.ArchitectureRefs[0] != "comp:loader" {
		t.Errorf("ArchitectureRefs = %v", pack.ArchitectureRefs)
	}
	if len(pack.ToolFactRefs) != 1 {
		t.Errorf("ToolFactRefs = %v", pack.ToolFactRefs)
	}
	if len(pack.RequiredEvidence) != 1 {
		t.Errorf("RequiredEvidence = %v", pack.RequiredEvidence)
	}
	if len(pack.CommonDefenses) != 1 || len(pack.CommonFalsePositives) != 1 {
		t.Errorf("playbook context not carried: defenses=%v fps=%v", pack.CommonDefenses, pack.CommonFalsePositives)
	}
	if len(pack.CoverageGaps) == 0 {
		t.Error("CoverageGaps should carry at least the attack-chain gap from the missing role")
	}
	if len(pack.MissingLinks) != 1 || !strings.Contains(pack.MissingLinks[0], "rollback_authority") {
		t.Errorf("MissingLinks = %v, want a rollback_authority entry", pack.MissingLinks)
	}
	if len(pack.TargetFiles) != 1 || pack.TargetFiles[0] != "core/crypto/signed_hdr.c" {
		t.Errorf("TargetFiles = %v, want the filled role's location", pack.TargetFiles)
	}
	if len(pack.TargetSymbols) != 1 || pack.TargetSymbols[0] != "shdr_load_pub_key" {
		t.Errorf("TargetSymbols = %v", pack.TargetSymbols)
	}
}

func TestBuildCasePack_NoMissingRolesMeansNoMissingLinks(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{TWEIDs: []string{"TWE-STATE-001"}})
	pack := investigations.BuildCasePack(inv, investigations.CasePackInput{CaseID: "case-fixed"})
	if len(pack.MissingLinks) != 0 {
		t.Errorf("MissingLinks = %v, want none", pack.MissingLinks)
	}
}
