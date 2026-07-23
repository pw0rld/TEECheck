package investigations

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// ValidationInput bundles the grounding context Validate checks an
// investigation's references against. Each field is independently
// optional: an empty ValidationInput performs no grounding (every
// reference is kept as-is) rather than dropping everything, so a caller
// that has not wired up one piece of context yet does not lose data it
// could not have validated anyway.
type ValidationInput struct {
	// Architecture grounds ArchitectureRefs: a ref naming an element or
	// relation ID not present in this model is dropped.
	Architecture artifacts.ArchitectureModel
	// Invariants grounds InvariantIDs: an id not present in this slice is
	// dropped.
	Invariants []artifacts.ProjectInvariant
	// RepoRoot, when set, grounds FilledRoles: a role location whose Path
	// does not resolve to a real file under RepoRoot is demoted to
	// MissingRoles — the same anti-hallucination discipline
	// internal/planner already applies to Candidate.Paths.
	RepoRoot string
}

// Adjustment records one place Validate changed what the caller (LLM)
// proposed — mirrors architecture.StateAdjustment / invariants.Adjustment:
// every adjustment is both returned here and folded into the
// investigation's own CoverageGaps (a schema-legal, free-text field) so a
// reader of the persisted JSON alone can see it happened.
type Adjustment struct {
	InvestigationID string `json:"investigation_id"`
	Kind            string `json:"kind"` // "unresolved_architecture_ref" | "unresolved_invariant_ref" | "unresolved_tool_fact_ref" | "unresolved_role_location"
	Reason          string `json:"reason"`
}

// Validate grounds every reference inv makes to the current run's context —
// exactly what §24's acceptance criterion "每个 Investigation 可追溯到 TWE、
// Invariant、ToolFact 和源码" asks a test to demonstrate. It never adds
// TWE/classification data (that is Build's job); it only removes or
// re-homes references that do not resolve, recording why.
func Validate(inv artifacts.TWEInvestigation, in ValidationInput) (artifacts.TWEInvestigation, []Adjustment) {
	var adjustments []Adjustment

	var archAdj []Adjustment
	inv, archAdj = validateArchitectureRefs(inv, in.Architecture)
	adjustments = append(adjustments, archAdj...)

	var invAdj []Adjustment
	inv, invAdj = validateInvariantRefs(inv, in.Invariants)
	adjustments = append(adjustments, invAdj...)

	var toolAdj []Adjustment
	inv, toolAdj = validateToolFactRefs(inv, in.RepoRoot)
	adjustments = append(adjustments, toolAdj...)

	var roleAdj []Adjustment
	inv, roleAdj = validateRoleLocations(inv, in.RepoRoot)
	adjustments = append(adjustments, roleAdj...)

	if len(adjustments) > 0 {
		var notes []string
		for _, adj := range adjustments {
			notes = append(notes, adj.Reason)
		}
		inv.CoverageGaps = dedupeSorted(append(append([]string{}, inv.CoverageGaps...), notes...))
	}

	// validateRoleLocations may have demoted a filled role to missing —
	// recompute the attack-chain-completeness lines against the now-current
	// MissingRoles rather than leaving Build's stale ones in place.
	inv.CoverageGaps = withFreshAttackChainGaps(inv)

	return inv, adjustments
}

func validateArchitectureRefs(inv artifacts.TWEInvestigation, model artifacts.ArchitectureModel) (artifacts.TWEInvestigation, []Adjustment) {
	valid := architectureIDs(model)
	var kept []string
	var adjustments []Adjustment
	for _, ref := range inv.ArchitectureRefs {
		if valid[ref] {
			kept = append(kept, ref)
			continue
		}
		reason := fmt.Sprintf("architecture_ref %q does not exist in the architecture model", ref)
		adjustments = append(adjustments, Adjustment{InvestigationID: inv.InvestigationID, Kind: "unresolved_architecture_ref", Reason: reason})
	}
	inv.ArchitectureRefs = kept
	return inv, adjustments
}

// architectureIDs is duplicated from invariants.architectureIDs rather than
// imported (that function is unexported): §22's precedent, restated in
// invariants.ValidateEvidence's doc comment, is that a small pure lookup
// like this is cheaper to keep independent per-package than to add a cross-
// package coupling for.
func architectureIDs(model artifacts.ArchitectureModel) map[string]bool {
	ids := map[string]bool{}
	add := func(elems []artifacts.ArchitectureElement) {
		for _, el := range elems {
			ids[el.ID] = true
		}
	}
	add(model.Parties)
	add(model.Components)
	add(model.Roles)
	add(model.Assets)
	add(model.TrustZones)
	add(model.Entrypoints)
	add(model.TrustAssumptions)
	add(model.DeploymentAssumptions)
	add(model.Unknowns)
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

func validateInvariantRefs(inv artifacts.TWEInvestigation, invariants []artifacts.ProjectInvariant) (artifacts.TWEInvestigation, []Adjustment) {
	valid := map[string]bool{}
	for _, i := range invariants {
		valid[i.InvariantID] = true
	}
	var kept []string
	var adjustments []Adjustment
	for _, ref := range inv.InvariantIDs {
		if valid[ref] {
			kept = append(kept, ref)
			continue
		}
		reason := fmt.Sprintf("invariant_id %q does not exist in the current project invariants", ref)
		adjustments = append(adjustments, Adjustment{InvestigationID: inv.InvestigationID, Kind: "unresolved_invariant_ref", Reason: reason})
	}
	inv.InvariantIDs = kept
	return inv, adjustments
}

// validateToolFactRefs drops any ToolFactRef that does not resolve to a
// file on disk. Refs are expected to be the absolute path
// trustirfacts.RunAndPersist / investigations.Persist returned (see
// internal/planner's fact_layer_query action) — this is a plain os.Stat,
// not a schema/content check, matching invariants.resolveEvidenceReference's
// path-only-evidence handling.
func validateToolFactRefs(inv artifacts.TWEInvestigation, repoRoot string) (artifacts.TWEInvestigation, []Adjustment) {
	var kept []string
	var adjustments []Adjustment
	for _, ref := range inv.ToolFactRefs {
		path := ref
		if !filepath.IsAbs(path) && repoRoot != "" {
			path = filepath.Join(repoRoot, ref)
		}
		if _, err := os.Stat(path); err != nil {
			reason := fmt.Sprintf("tool_fact_ref %q does not resolve to a persisted artifact: %v", ref, err)
			adjustments = append(adjustments, Adjustment{InvestigationID: inv.InvestigationID, Kind: "unresolved_tool_fact_ref", Reason: reason})
			continue
		}
		kept = append(kept, ref)
	}
	inv.ToolFactRefs = kept
	return inv, adjustments
}

// validateRoleLocations demotes any FilledRoles entry whose Path does not
// resolve to a real file under repoRoot into MissingRoles — the same
// anti-hallucination discipline internal/planner already applies to
// Candidate.Paths (see planner.normalizePath), applied here to investigation
// role evidence so a fabricated file location cannot masquerade as a filled
// role. A blank repoRoot skips this check entirely (nothing to resolve
// against) rather than dropping every role.
func validateRoleLocations(inv artifacts.TWEInvestigation, repoRoot string) (artifacts.TWEInvestigation, []Adjustment) {
	if repoRoot == "" || len(inv.FilledRoles) == 0 {
		return inv, nil
	}
	var adjustments []Adjustment
	kept := make(map[string]artifacts.ToolLocation, len(inv.FilledRoles))
	var demoted []string
	for role, loc := range inv.FilledRoles {
		full := loc.Path
		if !filepath.IsAbs(full) {
			full = filepath.Join(repoRoot, loc.Path)
		}
		if _, err := os.Stat(full); err != nil {
			reason := fmt.Sprintf("role %q location %q does not resolve to a real file under the repository", role, loc.Path)
			adjustments = append(adjustments, Adjustment{InvestigationID: inv.InvestigationID, Kind: "unresolved_role_location", Reason: reason})
			demoted = append(demoted, role)
			continue
		}
		kept[role] = loc
	}
	if len(kept) == 0 {
		kept = nil
	}
	inv.FilledRoles = kept
	if len(demoted) > 0 {
		missing := map[string]bool{}
		for _, r := range inv.MissingRoles {
			missing[r] = true
		}
		for _, r := range demoted {
			missing[r] = true
		}
		out := make([]string, 0, len(missing))
		for r := range missing {
			out = append(out, r)
		}
		sort.Strings(out)
		inv.MissingRoles = out
	}
	return inv, adjustments
}
