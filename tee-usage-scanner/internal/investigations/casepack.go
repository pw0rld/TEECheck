package investigations

import (
	"fmt"
	"sort"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
)

// CasePackInput is the identity and playbook-derived context BuildCasePack
// needs beyond the TWEInvestigation itself. CommonDefenses and
// CommonFalsePositives come from the matched TWE playbook(s)
// (twecontext.Playbook) — this package accepts them as plain strings rather
// than importing internal/twecontext, so a caller that has not loaded the
// playbook catalog can still build a (playbook-context-free) Case Pack.
type CasePackInput struct {
	CaseID   string
	Focus    string
	Priority string

	CommonDefenses       []string
	CommonFalsePositives []string
}

// BuildCasePack renders the bounded Case Pack (§10, §24 "Case Pack 修改")
// for one investigation: the related TWE/invariant IDs, the architecture
// slice and ToolFact refs the investigation actually used, the attack path
// it traced and the counter-evidence it found, its outstanding required
// evidence and coverage gaps, and the matched playbook's common defenses/
// false positives — everything Expert/Challenger need without re-deriving
// it from the full Architecture Model or TWE catalog (§11.3).
//
// Category is set to inv.Classification: standard/variant/composition/
// catalog_gap is exactly the axis §24 asks a Case Pack to carry, and it is
// already the one piece of investigation-level judgment this package makes.
// TargetFiles/TargetSymbols come from FilledRoles' locations — a
// representative set of real files (grounded by Validate before this is
// called), not the full repository.
func BuildCasePack(inv artifacts.TWEInvestigation, in CasePackInput) artifacts.CasePack {
	pack := artifacts.CasePack{
		CaseInvariants: contracts.MergeAll(nil, inv.CaseInvariants),
		SchemaVersion:  "teecheck.case_pack.v1",
		CaseID:         in.CaseID,
		Focus:          in.Focus,
		Category:       inv.Classification,
		Priority:       in.Priority,

		RelatedTWEs:          append([]string{}, inv.TWEIDs...),
		RelatedInvariants:    append([]string{}, inv.InvariantIDs...),
		ArchitectureRefs:     append([]string{}, inv.ArchitectureRefs...),
		ToolFactRefs:         append([]string{}, inv.ToolFactRefs...),
		RequiredEvidence:     append([]string{}, inv.RequiredEvidence...),
		CommonDefenses:       append([]string{}, in.CommonDefenses...),
		CommonFalsePositives: append([]string{}, in.CommonFalsePositives...),
		CoverageGaps:         append([]string{}, inv.CoverageGaps...),
		MissingLinks:         missingLinks(inv),

		// ObservedFlow and CounterEvidence are the two fields the
		// investigation produces that nothing else in the run can
		// reconstruct: the path the Investigator actually traced, and
		// what it found against its own hypothesis. Copied like every
		// slice above so a caller still editing its TWEInvestigation
		// cannot reach into the pack's backing array.
		ObservedFlow:    append([]artifacts.ToolPathStep{}, inv.ObservedFlow...),
		CounterEvidence: append([]string{}, inv.CounterEvidence...),
	}
	pack.TargetFiles, pack.TargetSymbols = targetsFromRoles(inv.FilledRoles)
	return pack
}

// missingLinks renders inv.MissingRoles as the specific, per-role "not
// located yet" statements §24 calls "missing links" — the Investigator's
// NEXT TASK list, not a vulnerability or safety conclusion (§7.5).
func missingLinks(inv artifacts.TWEInvestigation) []string {
	if len(inv.MissingRoles) == 0 {
		return nil
	}
	out := make([]string, 0, len(inv.MissingRoles))
	for _, role := range inv.MissingRoles {
		out = append(out, fmt.Sprintf("role %q not yet located in source", role))
	}
	return out
}

// targetsFromRoles extracts a stable, sorted (file, symbol) view from
// FilledRoles for CasePack.TargetFiles/TargetSymbols.
func targetsFromRoles(roles map[string]artifacts.ToolLocation) (files, symbols []string) {
	if len(roles) == 0 {
		return nil, nil
	}
	fileSet := map[string]bool{}
	symbolSet := map[string]bool{}
	for _, loc := range roles {
		if loc.Path != "" {
			fileSet[loc.Path] = true
		}
		if loc.Symbol != "" {
			symbolSet[loc.Symbol] = true
		}
	}
	for f := range fileSet {
		files = append(files, f)
	}
	for s := range symbolSet {
		symbols = append(symbols, s)
	}
	sort.Strings(files)
	sort.Strings(symbols)
	return files, symbols
}
