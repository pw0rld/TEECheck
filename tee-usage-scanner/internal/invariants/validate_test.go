package invariants

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// §22 / §3.4: "不允许把 proposed invariant 直接输出为 finding" starts with
// status itself only ever being proposed — EnforceProposedStatus is the
// mechanical gate.
func TestEnforceProposedStatus_OverwritesAnyOtherStatus(t *testing.T) {
	for _, bad := range []string{"", "grounded", "satisfied", "violated_candidate", "made_up"} {
		inv := artifacts.ProjectInvariant{InvariantID: "INV-1", Status: bad}
		got, adj := EnforceProposedStatus(inv)
		if got.Status != "proposed" {
			t.Errorf("status %q -> %q, want proposed", bad, got.Status)
		}
		if bad != "proposed" && adj == nil {
			t.Errorf("status %q: expected an Adjustment to be recorded", bad)
		}
	}
}

func TestEnforceProposedStatus_AlreadyProposedNoAdjustment(t *testing.T) {
	inv := artifacts.ProjectInvariant{InvariantID: "INV-1", Status: "proposed"}
	got, adj := EnforceProposedStatus(inv)
	if got.Status != "proposed" {
		t.Fatalf("status = %q", got.Status)
	}
	if adj != nil {
		t.Errorf("no-op case recorded an adjustment: %+v", adj)
	}
}

// §7.4: "允许生成无法归入现有 TWE 的 project-specific invariant 并标记 catalog
// gap" — but project-invariant.v1.json requires related_twes to be
// non-empty, so the catalog-gap signal has to survive that constraint.
func TestApplyCatalogGap_EmptyRelatedTWEsGetsSentinel(t *testing.T) {
	inv := artifacts.ProjectInvariant{InvariantID: "INV-1", RelatedTWEs: nil}
	got, adj := ApplyCatalogGap(inv)
	if len(got.RelatedTWEs) != 1 || got.RelatedTWEs[0] != CatalogGapTWEID {
		t.Fatalf("related_twes = %v, want [%s]", got.RelatedTWEs, CatalogGapTWEID)
	}
	if adj == nil || adj.Kind != "catalog_gap" {
		t.Fatalf("adjustment = %+v", adj)
	}
	found := false
	for _, u := range got.UnresolvedAssumptions {
		if strings.Contains(u, "catalog_gap") {
			found = true
		}
	}
	if !found {
		t.Errorf("catalog gap not recorded in unresolved_assumptions: %v", got.UnresolvedAssumptions)
	}
}

func TestApplyCatalogGap_RealTWEsUntouched(t *testing.T) {
	inv := artifacts.ProjectInvariant{InvariantID: "INV-1", RelatedTWEs: []string{"TWE-STATE-001"}}
	got, adj := ApplyCatalogGap(inv)
	if len(got.RelatedTWEs) != 1 || got.RelatedTWEs[0] != "TWE-STATE-001" {
		t.Fatalf("related_twes changed: %v", got.RelatedTWEs)
	}
	if adj != nil {
		t.Errorf("no-op case recorded an adjustment: %+v", adj)
	}
}

// Referential integrity: architecture_refs pointing at IDs that do not
// exist in the given model are invented architecture and must be stripped.
func TestValidateArchitectureRefs_DropsDanglingRefs(t *testing.T) {
	model := artifacts.ArchitectureModel{
		Assets: []artifacts.ArchitectureElement{{ID: "asset-wallet-state"}},
	}
	inv := artifacts.ProjectInvariant{
		InvariantID:      "INV-1",
		ArchitectureRefs: []string{"asset-wallet-state", "asset-does-not-exist"},
	}
	got, adjustments := ValidateArchitectureRefs(inv, model)
	if len(got.ArchitectureRefs) != 1 || got.ArchitectureRefs[0] != "asset-wallet-state" {
		t.Fatalf("architecture_refs = %v, want only the real ref kept", got.ArchitectureRefs)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %+v, want 1", adjustments)
	}
	found := false
	for _, u := range got.UnresolvedAssumptions {
		if strings.Contains(u, "asset-does-not-exist") {
			found = true
		}
	}
	if !found {
		t.Errorf("dangling ref not recorded in unresolved_assumptions: %v", got.UnresolvedAssumptions)
	}
}

func TestValidateArchitectureRefs_ResolvesRelationIDsToo(t *testing.T) {
	model := artifacts.ArchitectureModel{
		Boundaries: []artifacts.ArchitectureRelation{{ID: "boundary-1"}},
	}
	inv := artifacts.ProjectInvariant{InvariantID: "INV-1", ArchitectureRefs: []string{"boundary-1"}}
	got, adjustments := ValidateArchitectureRefs(inv, model)
	if len(got.ArchitectureRefs) != 1 {
		t.Fatalf("architecture_refs = %v, want boundary-1 kept", got.ArchitectureRefs)
	}
	if len(adjustments) != 0 {
		t.Errorf("adjustments = %+v, want none", adjustments)
	}
}

// Evidence citations get the same existence+range check architecture
// elements do.
func TestValidateEvidence_DropsUnresolvableCitations(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "core", "crypto", "signed_hdr.c")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("TEE_Result shdr_load_pub_key(void) {\n\treturn TEE_SUCCESS;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := artifacts.ProjectInvariant{
		InvariantID: "INV-1",
		Evidence: []artifacts.EvidenceReference{
			{Kind: "source", File: "core/crypto/signed_hdr.c", StartLine: 1, EndLine: 1},
			{Kind: "source", File: "core/crypto/missing.c", StartLine: 1, EndLine: 1},
		},
	}
	got, adjustments := ValidateEvidence(inv, repo)
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence = %+v, want the one resolvable citation kept", got.Evidence)
	}
	if len(adjustments) != 1 {
		t.Fatalf("adjustments = %+v, want 1", adjustments)
	}
}

// ─── Full pipeline via Validate ─────────────────────────────────────────

func TestValidate_RunsAllChecksTogether(t *testing.T) {
	model := artifacts.ArchitectureModel{
		Assets: []artifacts.ArchitectureElement{{ID: "asset-wallet-state"}},
	}
	inv := artifacts.ProjectInvariant{
		InvariantID:      "INV-1",
		Status:           "satisfied", // must be forced back to proposed
		RelatedTWEs:      nil,         // must get the catalog-gap sentinel
		ArchitectureRefs: []string{"asset-wallet-state", "asset-ghost"},
	}
	got, adjustments := Validate(inv, model, t.TempDir())

	if got.Status != "proposed" {
		t.Errorf("status = %q, want proposed", got.Status)
	}
	if len(got.RelatedTWEs) != 1 || got.RelatedTWEs[0] != CatalogGapTWEID {
		t.Errorf("related_twes = %v", got.RelatedTWEs)
	}
	if len(got.ArchitectureRefs) != 1 || got.ArchitectureRefs[0] != "asset-wallet-state" {
		t.Errorf("architecture_refs = %v", got.ArchitectureRefs)
	}
	// status_override + catalog_gap + unresolved_architecture_ref = 3
	if len(adjustments) != 3 {
		t.Fatalf("adjustments = %+v, want 3", adjustments)
	}
}
