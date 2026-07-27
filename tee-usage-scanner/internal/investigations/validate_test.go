package investigations_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/investigations"
)

func TestValidate_DropsUnresolvedArchitectureRef(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs:           []string{"TWE-STATE-001"},
		ArchitectureRefs: []string{"comp:loader", "comp:does-not-exist"},
	})
	model := artifacts.ArchitectureModel{
		Components: []artifacts.ArchitectureElement{{ID: "comp:loader", Kind: "component"}},
	}
	out, adjustments := investigations.Validate(inv, investigations.ValidationInput{Architecture: model})

	if len(out.ArchitectureRefs) != 1 || out.ArchitectureRefs[0] != "comp:loader" {
		t.Errorf("ArchitectureRefs = %v, want [comp:loader]", out.ArchitectureRefs)
	}
	if len(adjustments) != 1 || adjustments[0].Kind != "unresolved_architecture_ref" {
		t.Errorf("adjustments = %+v, want one unresolved_architecture_ref", adjustments)
	}
}

func TestValidate_DropsUnresolvedInvariantRef(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs:       []string{"TWE-STATE-001"},
		InvariantIDs: []string{"INV-STATE-001", "INV-DOES-NOT-EXIST"},
	})
	known := []artifacts.ProjectInvariant{{InvariantID: "INV-STATE-001"}}
	out, adjustments := investigations.Validate(inv, investigations.ValidationInput{Invariants: known})

	if len(out.InvariantIDs) != 1 || out.InvariantIDs[0] != "INV-STATE-001" {
		t.Errorf("InvariantIDs = %v, want [INV-STATE-001]", out.InvariantIDs)
	}
	if len(adjustments) != 1 || adjustments[0].Kind != "unresolved_invariant_ref" {
		t.Errorf("adjustments = %+v, want one unresolved_invariant_ref", adjustments)
	}
}

func TestValidate_DropsUnresolvedToolFactRef(t *testing.T) {
	repoRoot := t.TempDir()
	realFact := filepath.Join(repoRoot, "fact.json")
	if err := os.WriteFile(realFact, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs:       []string{"TWE-STATE-001"},
		ToolFactRefs: []string{realFact, filepath.Join(repoRoot, "missing-fact.json")},
	})
	out, adjustments := investigations.Validate(inv, investigations.ValidationInput{RepoRoot: repoRoot})

	if len(out.ToolFactRefs) != 1 || out.ToolFactRefs[0] != realFact {
		t.Errorf("ToolFactRefs = %v, want [%s]", out.ToolFactRefs, realFact)
	}
	if len(adjustments) != 1 || adjustments[0].Kind != "unresolved_tool_fact_ref" {
		t.Errorf("adjustments = %+v, want one unresolved_tool_fact_ref", adjustments)
	}
}

// TestValidate_DemotesHallucinatedRoleLocation is the role-level analogue of
// the candidate path-hallucination guard planner.go already applies:
// FilledRoles pointing at a file that does not exist under the repository
// must not survive validation as "filled" evidence.
func TestValidate_DemotesHallucinatedRoleLocation(t *testing.T) {
	repoRoot := t.TempDir()
	realFile := "core/crypto/signed_hdr.c"
	if err := os.MkdirAll(filepath.Join(repoRoot, "core", "crypto"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, realFile), []byte("// x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer":     {Path: realFile, StartLine: 262},
			"rollback_authority": {Path: "does/not/exist.c", StartLine: 10},
		},
	})
	if !investigations.AttackChainComplete(inv) {
		t.Fatalf("precondition: Build() alone (no repo grounding) should see both roles filled")
	}

	out, adjustments := investigations.Validate(inv, investigations.ValidationInput{RepoRoot: repoRoot})

	if _, ok := out.FilledRoles["claim_producer"]; !ok {
		t.Error("claim_producer points at a real file and must stay filled")
	}
	if _, ok := out.FilledRoles["rollback_authority"]; ok {
		t.Error("rollback_authority points at a nonexistent file and must not stay filled")
	}
	found := false
	for _, r := range out.MissingRoles {
		if r == "rollback_authority" {
			found = true
		}
	}
	if !found {
		t.Errorf("MissingRoles = %v, want rollback_authority demoted into it", out.MissingRoles)
	}
	if investigations.AttackChainComplete(out) {
		t.Error("AttackChainComplete = true after demotion, want false")
	}
	if len(adjustments) != 1 || adjustments[0].Kind != "unresolved_role_location" {
		t.Errorf("adjustments = %+v, want one unresolved_role_location", adjustments)
	}
	if !strings.Contains(strings.Join(out.CoverageGaps, " | "), "rollback_authority") {
		t.Errorf("CoverageGaps = %v, want the demoted role reflected after re-derivation", out.CoverageGaps)
	}
}

func TestValidate_BlankRepoRootSkipsRoleLocationCheck(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{
		TWEIDs: []string{"TWE-STATE-001"},
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer": {Path: "anything.c", StartLine: 1},
		},
	})
	out, adjustments := investigations.Validate(inv, investigations.ValidationInput{})
	if len(adjustments) != 0 {
		t.Errorf("adjustments = %+v, want none when RepoRoot is unset", adjustments)
	}
	if _, ok := out.FilledRoles["claim_producer"]; !ok {
		t.Error("claim_producer should be left untouched when there is nothing to validate against")
	}
}

func TestValidate_NoOpWhenEverythingResolves(t *testing.T) {
	inv := investigations.Build(investigations.WireInvestigation{TWEIDs: []string{"TWE-STATE-001"}})
	out, adjustments := investigations.Validate(inv, investigations.ValidationInput{})
	if len(adjustments) != 0 {
		t.Errorf("adjustments = %+v, want none", adjustments)
	}
	if out.InvestigationID != inv.InvestigationID {
		t.Error("Validate must not change the investigation ID")
	}
}

// TestValidateRoleLocations_DemotesHallucinatedSymbol exercises
// validateRoleLocations (invoked here through the exported Validate, since
// this file is package investigations_test and cannot call the unexported
// function directly) for the case a real audit hit: the file exists and the
// line is real, only the symbol is fabricated. This is the exact shape the
// 2026-07-27 audit found in inv-flow-001-3a998d336f97.json.
func TestValidateRoleLocations_DemotesHallucinatedSymbol(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src", "pk", "rsa")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "LTC_SET_ASN1(siginfo, 1, OCTET_STRING, tmpbuf, siglen);\nder_decode_sequence(out, outlen, siginfo, 2);\n"
	if err := os.WriteFile(filepath.Join(src, "rsa_verify_hash.c"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	inv := artifacts.TWEInvestigation{
		InvestigationID: "inv-test-001",
		FilledRoles: map[string]artifacts.ToolLocation{
			"checks_that_do_not_dominate": {
				Path:      "src/pk/rsa/rsa_verify_hash.c",
				StartLine: 141,
				Symbol:    "der_decode_sequence_flexi",
			},
		},
	}

	got, adjustments := investigations.Validate(inv, investigations.ValidationInput{RepoRoot: root})

	if _, still := got.FilledRoles["checks_that_do_not_dominate"]; still {
		t.Fatal("role with a symbol absent from the file must not stay filled")
	}
	if !containsString(got.MissingRoles, "checks_that_do_not_dominate") {
		t.Fatalf("demoted role must land in MissingRoles, got %v", got.MissingRoles)
	}
	var found bool
	for _, a := range adjustments {
		if a.Kind == "unresolved_role_symbol" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want an unresolved_role_symbol adjustment, got %+v", adjustments)
	}
}

func TestValidateRoleLocations_KeepsRealSymbol(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "a.c"), []byte("void der_decode_sequence(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := artifacts.TWEInvestigation{
		InvestigationID: "inv-test-002",
		FilledRoles: map[string]artifacts.ToolLocation{
			"r": {Path: "src/a.c", StartLine: 1, Symbol: "der_decode_sequence"},
		},
	}
	got, adjustments := investigations.Validate(inv, investigations.ValidationInput{RepoRoot: root})
	if _, ok := got.FilledRoles["r"]; !ok {
		t.Fatal("a role whose symbol really appears in the file must stay filled")
	}
	if len(adjustments) != 0 {
		t.Fatalf("want no adjustments, got %+v", adjustments)
	}
}

// An empty Symbol must behave exactly as before this change: the file
// existence check alone decides.
func TestValidateRoleLocations_EmptySymbolUnchanged(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "a.c"), []byte("nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := artifacts.TWEInvestigation{
		InvestigationID: "inv-test-003",
		FilledRoles: map[string]artifacts.ToolLocation{
			"r": {Path: "src/a.c", StartLine: 1},
		},
	}
	got, adjustments := investigations.Validate(inv, investigations.ValidationInput{RepoRoot: root})
	if _, ok := got.FilledRoles["r"]; !ok {
		t.Fatal("a role with no declared symbol must be unaffected by the symbol check")
	}
	if len(adjustments) != 0 {
		t.Fatalf("want no adjustments, got %+v", adjustments)
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
