package investigations_test

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/investigations"
)

// ─── Classification (§9.5, §24) ──────────────────────────────────────────

func TestBuild_ZeroTWEIDsIsCatalogGap(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{})
	if inv.Classification != investigations.ClassificationCatalogGap {
		t.Fatalf("Classification = %q, want %q", inv.Classification, investigations.ClassificationCatalogGap)
	}
	if len(inv.TWEIDs) != 1 || inv.TWEIDs[0] != investigations.CatalogGapTWEID {
		t.Fatalf("TWEIDs = %v, want the catalog-gap sentinel (schema requires minItems:1)", inv.TWEIDs)
	}
}

func TestBuild_MultipleTWEIDsIsComposition(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001", "TWE-CONFIG-WEAK-MODE"},
	})
	if inv.Classification != investigations.ClassificationComposition {
		t.Fatalf("Classification = %q, want %q", inv.Classification, investigations.ClassificationComposition)
	}
}

func TestBuild_SingleTWEIDDefaultsToStandard(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{TWEIDs: []string{"TWE-STATE-001"}})
	if inv.Classification != investigations.ClassificationStandard {
		t.Fatalf("Classification = %q, want %q", inv.Classification, investigations.ClassificationStandard)
	}
}

func TestBuild_SingleTWEIDHonorsRequestedVariant(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"}, Classification: "variant",
	})
	if inv.Classification != investigations.ClassificationVariant {
		t.Fatalf("Classification = %q, want %q (caller's standard/variant opinion should be honored for exactly one TWE)", inv.Classification, investigations.ClassificationVariant)
	}
}

func TestBuild_RequestedClassificationIgnoredForCompositionAndGap(t *testing.T) {
	// A caller cannot talk its way out of the structural composition/gap
	// rules by requesting "standard" — those two cases are never taken on
	// the caller's word (see Build's doc comment).
	comp := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001", "TWE-CONFIG-WEAK-MODE"}, Classification: "standard",
	})
	if comp.Classification != investigations.ClassificationComposition {
		t.Errorf("composition case: Classification = %q, want %q", comp.Classification, investigations.ClassificationComposition)
	}
	gap := investigations.Build(investigations.WireInvestigation{Classification: "standard"})
	if gap.Classification != investigations.ClassificationCatalogGap {
		t.Errorf("catalog_gap case: Classification = %q, want %q", gap.Classification, investigations.ClassificationCatalogGap)
	}
}

// ─── Role reconciliation ─────────────────────────────────────────────────

func TestBuild_FilledRoleWinsOverStaleMissingNote(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer": {Path: "core/crypto/signed_hdr.c", StartLine: 262},
		},
		MissingRoles: []string{"claim_producer", "rollback_authority"},
	})
	if _, ok := inv.FilledRoles["claim_producer"]; !ok {
		t.Error("claim_producer should be in FilledRoles")
	}
	if len(inv.MissingRoles) != 1 || inv.MissingRoles[0] != "rollback_authority" {
		t.Errorf("MissingRoles = %v, want exactly [rollback_authority] (filled role must not also appear as missing)", inv.MissingRoles)
	}
}

func TestBuild_MissingRolesDedupedAndSorted(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs:       []string{"TWE-STATE-001"},
		MissingRoles: []string{"rollback_authority", "claim_producer", "rollback_authority", ""},
	})
	want := []string{"claim_producer", "rollback_authority"}
	if len(inv.MissingRoles) != len(want) {
		t.Fatalf("MissingRoles = %v, want %v", inv.MissingRoles, want)
	}
	for i, r := range want {
		if inv.MissingRoles[i] != r {
			t.Errorf("MissingRoles[%d] = %q, want %q", i, inv.MissingRoles[i], r)
		}
	}
}

// ─── Attack-chain completeness (§7.5, §24) ───────────────────────────────

func TestBuild_MissingRoleAndOutstandingEvidenceProduceCoverageGapsNotAVerdict(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs:           []string{"TWE-STATE-001"},
		MissingRoles:     []string{"rollback_authority"},
		RequiredEvidence: []string{"freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input"},
	})
	if investigations.AttackChainComplete(inv) {
		t.Fatal("AttackChainComplete = true, want false — a missing role must not read as a demonstrated chain")
	}
	joined := strings.Join(inv.CoverageGaps, " | ")
	if !strings.Contains(joined, "missing role") {
		t.Errorf("CoverageGaps = %v, want a note about the missing role", inv.CoverageGaps)
	}
	if !strings.Contains(joined, "outstanding required evidence") {
		t.Errorf("CoverageGaps = %v, want a note about outstanding required evidence", inv.CoverageGaps)
	}
	// artifacts.TWEInvestigation has no verdict field at all — the only way
	// to check "the Planner did not conclude vulnerable/safe" is that no
	// such field exists to have been set. This is a structural assertion,
	// not a text-content one.
}

func TestBuild_AllRolesFilledAndEvidenceSatisfiedIsAttackChainComplete(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer":     {Path: "core/crypto/signed_hdr.c", StartLine: 262},
			"rollback_authority": {Path: "core/kernel/ree_fs_ta.c", StartLine: 400},
		},
	})
	if !investigations.AttackChainComplete(inv) {
		t.Fatalf("AttackChainComplete = false, want true; CoverageGaps=%v", inv.CoverageGaps)
	}
	for _, gap := range inv.CoverageGaps {
		if strings.Contains(gap, "attack chain incomplete") {
			t.Errorf("CoverageGaps unexpectedly contains a stale attack-chain gap: %v", inv.CoverageGaps)
		}
	}
}

// ─── Deterministic IDs ────────────────────────────────────────────────────

func TestBuild_IdenticalInputProducesTheSameID(t *testing.T) {
	w := investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer": {Path: "core/crypto/signed_hdr.c", StartLine: 262},
		},
	}
	a := investigations.Build(w)
	b := investigations.Build(w)
	if a.InvestigationID != b.InvestigationID {
		t.Errorf("InvestigationID not deterministic: %q vs %q", a.InvestigationID, b.InvestigationID)
	}
	if a.InvestigationID == "" {
		t.Error("InvestigationID must not be empty")
	}
}

func TestBuild_DifferentFindingsProduceDifferentIDs(t *testing.T) {
	vulnerable := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer": {Path: "core/crypto/signed_hdr.c", StartLine: 262},
		},
		MissingRoles: []string{"version_propagated_to_authority"},
	})
	fixed := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer":                  {Path: "core/crypto/signed_hdr.c", StartLine: 262},
			"version_propagated_to_authority": {Path: "core/crypto/signed_hdr.c", StartLine: 320},
		},
	})
	if vulnerable.InvestigationID == fixed.InvestigationID {
		t.Error("vulnerable and fixed investigations must not collide on InvestigationID")
	}
}
