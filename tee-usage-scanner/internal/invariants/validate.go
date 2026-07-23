package invariants

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// CatalogGapTWEID is the sentinel related_twes entry used when a
// project-specific obligation fits no existing TWE playbook — see the
// package doc comment for why this exists (project-invariant.v1.json
// requires related_twes to be non-empty, so "maps to zero TWEs" cannot be
// expressed by leaving the array empty).
const CatalogGapTWEID = "TWE-CATALOG-GAP"

// Adjustment records one place validation changed what the model proposed
// — a status override, a dropped architecture_ref, a dropped evidence
// citation, or a catalog-gap sentinel insertion. Mirrors
// architecture.StateAdjustment's "recorded, not just applied" contract
// (§22): every adjustment is both returned here (for callers/tests) and
// folded into the invariant's own UnresolvedAssumptions (a schema-legal,
// free-text field) so a reader of the persisted JSON alone can see it
// happened.
type Adjustment struct {
	InvariantID string `json:"invariant_id"`
	Kind        string `json:"kind"` // "status_override" | "unresolved_architecture_ref" | "dropped_evidence" | "catalog_gap"
	Reason      string `json:"reason"`
}

// EnforceProposedStatus overwrites Status to "proposed" unconditionally.
// §3.4: "Invariant 初始状态只能是 proposed" — this is the mechanical form of
// that rule; nothing the model wrote for Status is ever read.
func EnforceProposedStatus(inv artifacts.ProjectInvariant) (artifacts.ProjectInvariant, *Adjustment) {
	const proposed = "proposed"
	if inv.Status == proposed {
		inv.Status = proposed
		return inv, nil
	}
	adj := &Adjustment{InvariantID: inv.InvariantID, Kind: "status_override",
		Reason: fmt.Sprintf("model-declared status %q overwritten; the Invariant Agent may only emit proposed (§3.4)", inv.Status)}
	inv.Status = proposed
	return inv, adj
}

// ApplyCatalogGap inserts CatalogGapTWEID as the sole related_twes entry
// when the model left related_twes empty (schema-illegal on its own —
// related_twes has minItems: 1), and records an unresolved_assumptions
// entry explaining why. An invariant that already names a real TWE is
// untouched.
func ApplyCatalogGap(inv artifacts.ProjectInvariant) (artifacts.ProjectInvariant, *Adjustment) {
	if len(inv.RelatedTWEs) > 0 {
		return inv, nil
	}
	reason := "no existing TWE playbook covers this obligation (catalog gap); related_twes set to the sentinel " + CatalogGapTWEID
	inv.RelatedTWEs = []string{CatalogGapTWEID}
	inv.UnresolvedAssumptions = append(inv.UnresolvedAssumptions, "catalog_gap: "+reason)
	return inv, &Adjustment{InvariantID: inv.InvariantID, Kind: "catalog_gap", Reason: reason}
}

// ValidateArchitectureRefs strips any architecture_refs entry that does not
// name a real element or relation ID in model, recording why. This is the
// referential-integrity half of "invented architecture" prevention for
// invariants: an invariant that cites a nonexistent architecture element is
// exactly as ungrounded as an architecture element with a broken source
// citation, just one layer up.
func ValidateArchitectureRefs(inv artifacts.ProjectInvariant, model artifacts.ArchitectureModel) (artifacts.ProjectInvariant, []Adjustment) {
	valid := architectureIDs(model)
	var kept []string
	var adjustments []Adjustment
	for _, ref := range inv.ArchitectureRefs {
		if valid[ref] {
			kept = append(kept, ref)
			continue
		}
		reason := fmt.Sprintf("architecture_ref %q does not exist in the architecture model", ref)
		inv.UnresolvedAssumptions = append(inv.UnresolvedAssumptions, reason)
		adjustments = append(adjustments, Adjustment{InvariantID: inv.InvariantID, Kind: "unresolved_architecture_ref", Reason: reason})
	}
	inv.ArchitectureRefs = kept
	return inv, adjustments
}

func architectureIDs(model artifacts.ArchitectureModel) map[string]bool {
	ids := map[string]bool{}
	for _, el := range model.Parties {
		ids[el.ID] = true
	}
	for _, el := range model.Components {
		ids[el.ID] = true
	}
	for _, el := range model.Roles {
		ids[el.ID] = true
	}
	for _, el := range model.Assets {
		ids[el.ID] = true
	}
	for _, el := range model.TrustZones {
		ids[el.ID] = true
	}
	for _, el := range model.Entrypoints {
		ids[el.ID] = true
	}
	for _, el := range model.TrustAssumptions {
		ids[el.ID] = true
	}
	for _, el := range model.DeploymentAssumptions {
		ids[el.ID] = true
	}
	for _, el := range model.Unknowns {
		ids[el.ID] = true
	}
	for _, rel := range model.Boundaries {
		ids[rel.ID] = true
	}
	for _, rel := range model.DataFlows {
		ids[rel.ID] = true
	}
	for _, rel := range model.StateLifecycles {
		ids[rel.ID] = true
	}
	return ids
}

// ValidateEvidence drops any Evidence entry that does not resolve against
// repoRoot, recording why — the same existence+range check
// architecture.checkEvidence performs (see that function's doc comment for
// why path-only and artifact_ref-only evidence are handled specially), but
// duplicated here rather than shared: internal/artifacts stays a pure,
// I/O-free types package (see EvidenceReference.CitedBytes' doc comment),
// and internal/invariants has no reason to import internal/architecture
// just for this one small orchestration.
func ValidateEvidence(inv artifacts.ProjectInvariant, repoRoot string) (artifacts.ProjectInvariant, []Adjustment) {
	var kept []artifacts.EvidenceReference
	var adjustments []Adjustment
	for _, ref := range inv.Evidence {
		if err := resolveEvidenceReference(ref, repoRoot); err != nil {
			reason := fmt.Sprintf("evidence %s: %v", ref.File, err)
			adjustments = append(adjustments, Adjustment{InvariantID: inv.InvariantID, Kind: "dropped_evidence", Reason: reason})
			continue
		}
		kept = append(kept, ref)
	}
	inv.Evidence = kept
	return inv, adjustments
}

func resolveEvidenceReference(ref artifacts.EvidenceReference, repoRoot string) error {
	if ref.File == "" {
		if ref.ArtifactRef != "" {
			return nil
		}
		return fmt.Errorf("neither file nor artifact_ref set")
	}
	if ref.StartLine < 1 {
		abs := ref.File
		if !filepath.IsAbs(abs) && repoRoot != "" {
			abs = filepath.Join(repoRoot, ref.File)
		}
		_, err := os.Stat(abs)
		return err
	}
	_, err := citations.Resolve(ref.CitedBytes(), repoRoot)
	return err
}

// Validate runs the full validation pipeline §22 requires on one invariant:
// status enforcement, catalog-gap handling, architecture_ref referential
// integrity, and evidence citation checking — in that order, so an
// invariant that started with no related_twes still gets its
// unresolved_assumptions note before architecture_ref stripping appends
// its own.
func Validate(inv artifacts.ProjectInvariant, model artifacts.ArchitectureModel, repoRoot string) (artifacts.ProjectInvariant, []Adjustment) {
	var adjustments []Adjustment

	inv, statusAdj := EnforceProposedStatus(inv)
	if statusAdj != nil {
		adjustments = append(adjustments, *statusAdj)
	}

	inv, gapAdj := ApplyCatalogGap(inv)
	if gapAdj != nil {
		adjustments = append(adjustments, *gapAdj)
	}

	inv, refAdj := ValidateArchitectureRefs(inv, model)
	adjustments = append(adjustments, refAdj...)

	inv, evAdj := ValidateEvidence(inv, repoRoot)
	adjustments = append(adjustments, evAdj...)

	return inv, adjustments
}
