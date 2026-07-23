package investigations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/invariants"
)

// Classification values, matching artifacts.TWEInvestigation.Classification
// (§9.5) and schemas/twe-investigation.v1.json's enum exactly.
const (
	ClassificationStandard    = "standard"
	ClassificationVariant     = "variant"
	ClassificationComposition = "composition"
	ClassificationCatalogGap  = "catalog_gap"
)

// CatalogGapTWEID is the sentinel twe_ids entry for a catalog_gap
// investigation. It is invariants.CatalogGapTWEID, not a second constant
// with the same value — §9.3's doc comment on ProjectInvariant.Classification
// is explicit that a catalog-gap Invariant and a catalog-gap Investigation
// point at the same sentinel, so one authoritative value backs both.
const CatalogGapTWEID = invariants.CatalogGapTWEID

// WireInvestigation is the loosely-typed shape a caller (typically the
// Planner LLM's `done` payload, see internal/planner) declares one
// investigation as. Field names and JSON tags mirror
// artifacts.TWEInvestigation directly so a caller holding raw JSON can
// unmarshal straight into this type. It omits schema_version and
// investigation_id (Build derives both — an LLM-supplied ID would not be
// reliably unique or reproducible) and repurposes "classification" as the
// caller's OPINION rather than the final value — see Build's doc comment on
// why only the standard/variant distinction is taken on the caller's word.
type WireInvestigation struct {
	TWEIDs           []string                          `json:"twe_ids"`
	InvariantIDs     []string                          `json:"invariant_ids,omitempty"`
	ArchitectureRefs []string                          `json:"architecture_refs,omitempty"`
	Classification   string                            `json:"classification,omitempty"`
	ObservedFlow     []artifacts.ToolPathStep          `json:"observed_flow,omitempty"`
	FilledRoles      map[string]artifacts.ToolLocation `json:"filled_roles,omitempty"`
	MissingRoles     []string                          `json:"missing_roles,omitempty"`
	RequiredEvidence []string                          `json:"required_evidence,omitempty"`
	CounterEvidence  []string                          `json:"counterevidence,omitempty"`
	CoverageGaps     []string                          `json:"coverage_gaps,omitempty"`
	ToolFactRefs     []string                          `json:"tool_fact_refs,omitempty"`
}

// Build turns w into the canonical artifacts.TWEInvestigation shape:
//
//   - Classification is derived structurally from len(TWEIDs), not simply
//     copied from w.Classification (§7.5: the Planner does not own the
//     final verdict, and "how many TWEs matched" is a structural fact this
//     package can check itself, not a judgment call to defer). Zero TWE IDs
//     becomes catalog_gap (with the sentinel twe_ids entry — the schema
//     requires minItems:1, same reasoning as invariants.ApplyCatalogGap).
//     More than one becomes composition (§7.5: "动态组合多个 TWE"). Exactly
//     one TWE ID takes the caller's standard/variant opinion
//     (w.Classification), defaulting to standard when unset or unrecognized
//     — Build never invents "variant" on its own, since distinguishing a
//     variant from a textbook case is exactly the semantic judgment §7.6
//     assigns to the Expert Agent, not the Investigator.
//   - FilledRoles and MissingRoles are reconciled: a role present in both
//     is treated as filled (evidence wins over an earlier "still missing"
//     note), and MissingRoles is deduplicated and sorted.
//   - RequiredEvidence, CounterEvidence, ToolFactRefs, InvariantIDs and
//     ArchitectureRefs are deduplicated and sorted for stable output.
//   - CoverageGaps is extended with the attack-chain completeness gaps
//     (see attackChainGaps) so a reader of CoverageGaps alone sees why the
//     chain is not yet demonstrated, without cross-referencing
//     MissingRoles/RequiredEvidence themselves.
//   - InvestigationID is derived deterministically from the investigation's
//     content when not already set by Validate/a later stage — see
//     deriveID.
//
// Build never drops or downgrades a reference for being ungrounded — that
// is Validate's job (it needs the ArchitectureModel/ProjectInvariants/
// repository Build does not have access to). Build only normalizes shape.
func Build(w WireInvestigation) artifacts.TWEInvestigation {
	inv := artifacts.TWEInvestigation{
		SchemaVersion:    artifacts.SchemaVersionTWEInvestigationV1,
		InvariantIDs:     dedupeSorted(w.InvariantIDs),
		ArchitectureRefs: dedupeSorted(w.ArchitectureRefs),
		ObservedFlow:     w.ObservedFlow,
		RequiredEvidence: dedupeSorted(w.RequiredEvidence),
		CounterEvidence:  dedupeSorted(w.CounterEvidence),
		ToolFactRefs:     dedupeSorted(w.ToolFactRefs),
	}

	inv.TWEIDs, inv.Classification = classify(w.TWEIDs, w.Classification)
	inv.FilledRoles, inv.MissingRoles = reconcileRoles(w.FilledRoles, w.MissingRoles)
	inv.CoverageGaps = dedupeSorted(w.CoverageGaps)

	inv.CoverageGaps = withFreshAttackChainGaps(inv)
	inv.InvestigationID = deriveID(inv)
	return inv
}

func classify(tweIDs []string, requested string) ([]string, string) {
	ids := dedupeSorted(tweIDs)
	switch {
	case len(ids) == 0:
		return []string{CatalogGapTWEID}, ClassificationCatalogGap
	case len(ids) > 1:
		return ids, ClassificationComposition
	default:
		if requested == ClassificationVariant {
			return ids, ClassificationVariant
		}
		return ids, ClassificationStandard
	}
}

// reconcileRoles merges filled and a caller-declared missing list: a role
// with a location is always "filled", even if the same caller also listed
// it as missing (evidence found this round wins over a stale note from an
// earlier round). Returns a nil map/slice (not an empty one) when there is
// nothing to report, matching artifacts.TWEInvestigation's omitempty tags.
func reconcileRoles(filled map[string]artifacts.ToolLocation, missing []string) (map[string]artifacts.ToolLocation, []string) {
	var outFilled map[string]artifacts.ToolLocation
	if len(filled) > 0 {
		outFilled = make(map[string]artifacts.ToolLocation, len(filled))
		for role, loc := range filled {
			outFilled[role] = loc
		}
	}
	seen := map[string]bool{}
	var outMissing []string
	for _, role := range missing {
		role = strings.TrimSpace(role)
		if role == "" || seen[role] {
			continue
		}
		if _, isFilled := outFilled[role]; isFilled {
			continue
		}
		seen[role] = true
		outMissing = append(outMissing, role)
	}
	sort.Strings(outMissing)
	return outFilled, outMissing
}

// attackChainGapPrefix tags the CoverageGaps lines attackChainGaps
// generates, so withFreshAttackChainGaps can find and replace them without
// disturbing any other (caller-declared or Validate-derived) gap text that
// happens to already be in CoverageGaps.
const attackChainGapPrefix = "attack chain incomplete: "

// attackChainGaps reports the §7.5/§24 "attack-chain completeness check" as
// human-readable coverage gap text: a missing role or an outstanding
// required-evidence item both mean the flow from attacker-controlled input
// to the authority point is not yet demonstrated end to end. See
// AttackChainComplete for the boolean form other packages can check without
// re-parsing this text.
func attackChainGaps(inv artifacts.TWEInvestigation) []string {
	var gaps []string
	if len(inv.MissingRoles) > 0 {
		gaps = append(gaps, fmt.Sprintf("%smissing role(s) %s", attackChainGapPrefix, strings.Join(inv.MissingRoles, ", ")))
	}
	if len(inv.RequiredEvidence) > 0 {
		gaps = append(gaps, fmt.Sprintf("%soutstanding required evidence: %s", attackChainGapPrefix, strings.Join(inv.RequiredEvidence, "; ")))
	}
	return gaps
}

// withFreshAttackChainGaps recomputes the attack-chain-completeness lines in
// inv.CoverageGaps against inv's CURRENT MissingRoles/RequiredEvidence,
// replacing any stale lines a prior Build/Validate pass added (identifiable
// by attackChainGapPrefix) rather than accumulating duplicates as
// MissingRoles changes across a Build → Validate pipeline (e.g. Validate
// demoting a hallucinated role location adds a new missing role after Build
// already ran).
func withFreshAttackChainGaps(inv artifacts.TWEInvestigation) []string {
	var kept []string
	for _, gap := range inv.CoverageGaps {
		if strings.HasPrefix(gap, attackChainGapPrefix) {
			continue
		}
		kept = append(kept, gap)
	}
	return dedupeSorted(append(kept, attackChainGaps(inv)...))
}

// AttackChainComplete reports whether inv has every role filled and every
// outstanding required-evidence item resolved — the structural precondition
// for treating inv.ObservedFlow as a demonstrated attack path. It is
// necessary, not sufficient: this package never itself concludes
// vulnerability or safety (§7.5) — Expert/Challenger/Verifier still judge
// what a complete chain actually means for this project.
func AttackChainComplete(inv artifacts.TWEInvestigation) bool {
	return len(inv.MissingRoles) == 0 && len(inv.RequiredEvidence) == 0
}

// deriveID computes a deterministic investigation ID from the parts of inv
// that identify what was investigated and what was found, so an identical
// investigation (same TWEs, same architecture refs, same filled/missing
// roles) always gets the same ID — the same idempotency property
// trustirfacts.Request.factID gives ToolFacts.
func deriveID(inv artifacts.TWEInvestigation) string {
	type keyed struct {
		TWEIDs           []string
		ArchitectureRefs []string
		FilledRoles      map[string]artifacts.ToolLocation
		MissingRoles     []string
	}
	data, err := json.Marshal(keyed{
		TWEIDs:           inv.TWEIDs,
		ArchitectureRefs: inv.ArchitectureRefs,
		FilledRoles:      inv.FilledRoles,
		MissingRoles:     inv.MissingRoles,
	})
	if err != nil {
		// keyed is plain data (strings/maps of a struct with only string/int
		// fields) — json.Marshal on it cannot fail.
		panic(fmt.Sprintf("investigations: marshal id input: %v", err))
	}
	sum := sha256.Sum256(data)

	prefix := "gap"
	if len(inv.TWEIDs) > 0 && inv.TWEIDs[0] != CatalogGapTWEID {
		prefix = strings.ToLower(strings.TrimPrefix(inv.TWEIDs[0], "TWE-"))
	}
	return fmt.Sprintf("inv-%s-%s", prefix, hex.EncodeToString(sum[:])[:12])
}

// dedupeSorted trims, deduplicates, and sorts values, returning nil (not an
// empty slice) for empty input so callers get the same "omit when empty"
// JSON behavior artifacts.TWEInvestigation's omitempty tags expect.
func dedupeSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
