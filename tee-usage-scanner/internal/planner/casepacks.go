package planner

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// priorityRank orders priorities so a merge can keep the higher one.
var priorityRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// BuildFromCandidate converts one planner candidate into a "thin" Case Pack:
// it carries where to look and why, but none of the TWE playbook knowledge a
// TWEInvestigation-derived pack carries. Thin packs exist so that a run whose
// model emitted candidates but no investigations still produces reviewable
// cases — investigations is an optional field in the done payload, and its
// reliability on large repositories has never been measured.
func BuildFromCandidate(cand artifacts.Candidate, manifest artifacts.Manifest, idx int) artifacts.CasePack {
	repoName := sanitizeSlug(filepath.Base(manifest.LocalPath))
	if repoName == "" {
		repoName = "repo"
	}
	commit := manifest.Commit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	return artifacts.CasePack{
		SchemaVersion: "teecheck.case_pack.v1",
		CaseID:        fmt.Sprintf("%s@%s:%s:candidate:%03d", repoName, commit, sanitizeSlug(manifest.Focus), idx+1),
		Focus:         manifest.Focus,
		Category:      categoryForKind(cand.Kind),
		Priority:      cand.Priority,
		TargetFiles:   append([]string{}, cand.Paths...),
		TargetSymbols: append([]string{}, cand.Symbols...),
		WhySelected:   append([]string{}, cand.WhySelected...),
	}
}

// categoryForKind mirrors internal/cases' caseTemplate (internal/cases/run.go:269)
// insofar as it returns the same category string for the same kind: an
// identity mapping for the five known kinds and "boundary" for anything else,
// including "". It is duplicated rather than exported from there on purpose:
// exporting it would make the llm path import the legacy case-building
// package, which this change exists to disentangle — the same reasoning
// already recorded on sanitizeSlug in this file. Unlike caseTemplate, this
// helper does not produce obligations or open-questions lists; those are
// deliberately retired on the candidate path.
func categoryForKind(kind string) string {
	switch kind {
	case "attestation", "authorization", "state_machine", "key_management", "fallback":
		return kind
	default:
		return "boundary"
	}
}

// targetKey canonicalizes a target-file set for equality checks.
func targetKey(p artifacts.CasePack) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(p.TargetFiles))
	for _, f := range p.TargetFiles {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\x00")
}

// SameReviewTarget conservatively identifies repeated review work. Explicitly
// different symbols or categories stay separate even when they share a file.
// An expanded evidence window may merge when its files contain the other
// window and the symbol matches, or when the same main file/category is known.
func SameReviewTarget(a, b artifacts.CasePack) bool {
	if len(a.CaseInvariants) > 0 || len(b.CaseInvariants) > 0 {
		// An untyped candidate has no property identity to compare safely.
		if len(a.CaseInvariants) == 0 || len(b.CaseInvariants) == 0 {
			return false
		}
		return contractProperties(a.CaseInvariants) == contractProperties(b.CaseInvariants)
	}
	if targetKey(a) == "" || targetKey(b) == "" {
		return false
	}
	sharedSymbol := false
	for _, x := range a.TargetSymbols {
		for _, y := range b.TargetSymbols {
			if x != "" && x == y {
				sharedSymbol = true
			}
		}
	}
	if len(a.TargetSymbols) > 0 && len(b.TargetSymbols) > 0 && !sharedSymbol {
		return false
	}
	aCategory, bCategory := reviewCategory(a.Category), reviewCategory(b.Category)
	if aCategory != "" && bCategory != "" && aCategory != bCategory {
		return false
	}
	if targetKey(a) == targetKey(b) {
		return true
	}
	if sharedSymbol && (targetSubset(a.TargetFiles, b.TargetFiles) || targetSubset(b.TargetFiles, a.TargetFiles)) {
		return true
	}
	return aCategory != "" && aCategory == bCategory && a.TargetFiles[0] == b.TargetFiles[0]
}

// Investigation classification and vulnerability category are distinct axes
// currently stored in the same legacy field. "standard" is not a competing
// issue category to "state_machine", so it must not prevent a rich/thin merge.
func reviewCategory(category string) string {
	switch category {
	case "standard", "variant", "composition", "catalog_gap":
		return ""
	default:
		return category
	}
}

func targetSubset(a, b []string) bool {
	set := map[string]bool{}
	for _, p := range b {
		set[p] = true
	}
	for _, p := range a {
		if !set[p] {
			return false
		}
	}
	return len(a) > 0
}

func matchingPack(p artifacts.CasePack, packs []artifacts.CasePack) int {
	for i, existing := range packs {
		if SameReviewTarget(p, existing) {
			return i
		}
	}
	return -1
}

// Merge combines one pass's rich investigation packs with thin candidates.
// Rich packs retain separate identities here; matching thin candidates fold
// into the earliest compatible target. Cross-pass DedupePacks uses the same
// conservative target comparison. Empty targets are not review units.
func Merge(rich, thin []artifacts.CasePack) []artifacts.CasePack {
	var out []artifacts.CasePack

	for _, p := range rich {
		key := targetKey(p)
		if key == "" {
			continue
		}
		out = append(out, p)
	}
	for _, p := range thin {
		key := targetKey(p)
		if key == "" {
			continue
		}
		if at := matchingPack(p, out); at >= 0 {
			out[at] = absorb(out[at], p)
			continue
		}
		out = append(out, p)
	}
	return out
}

// hasInvestigationKnowledge reports whether a pack carries any field that
// only a TWEInvestigation-derived ("rich") pack can have
// (internal/investigations.BuildCasePack sets them; BuildFromCandidate leaves
// every one of them empty). It is the single richness predicate in this file:
// absorb uses it to pick which side of a collapse survives, and DedupePacks
// uses it to keep the informative packs out of the --max-cases truncation
// tail.
//
// It deliberately looks at the whole investigation-only field set rather than
// at RelatedTWEs alone. An investigation that declared no twe_ids still
// yields a pack with real RequiredEvidence / CoverageGaps / ArchitectureRefs
// / MissingLinks; keying on RelatedTWEs would file that pack with the thin
// ones and truncate it first, which inverts the intent.
//
// TargetSymbols is NOT part of the predicate: thin packs carry it too
// (BuildFromCandidate copies cand.Symbols), so it says nothing about origin.
func hasInvestigationKnowledge(p artifacts.CasePack) bool {
	if len(p.CaseInvariants) > 0 {
		return true
	}
	return len(p.RelatedTWEs) > 0 ||
		len(p.RelatedInvariants) > 0 ||
		len(p.ArchitectureRefs) > 0 ||
		len(p.ToolFactRefs) > 0 ||
		len(p.RequiredEvidence) > 0 ||
		len(p.MissingLinks) > 0 ||
		len(p.CommonDefenses) > 0 ||
		len(p.CommonFalsePositives) > 0 ||
		len(p.CoverageGaps) > 0 ||
		len(p.CounterEvidence) > 0 ||
		len(p.ObservedFlow) > 0
}

// absorb combines evidence for one review target. The richer pack supplies
// CaseID/Category; ties preserve the first occurrence. Every unordered evidence
// field is unioned without mutating either input. ObservedFlow remains one
// coherent trace: use the primary's path, falling back to the other's if empty.
func absorb(base, extra artifacts.CasePack) artifacts.CasePack {
	primary, other := base, extra
	if !hasInvestigationKnowledge(base) && hasInvestigationKnowledge(extra) {
		primary, other = extra, base
	}

	out := primary
	out.ContractRequired = primary.ContractRequired || other.ContractRequired
	out.TargetFiles = unionStrings(primary.TargetFiles, other.TargetFiles)
	out.WhySelected = unionStrings(primary.WhySelected, other.WhySelected)
	out.TargetSymbols = unionStrings(primary.TargetSymbols, other.TargetSymbols)
	out.CaseInvariants = contracts.MergeAll(primary.CaseInvariants, other.CaseInvariants)
	out.RelatedTWEs = unionStrings(primary.RelatedTWEs, other.RelatedTWEs)
	out.RelatedInvariants = unionStrings(primary.RelatedInvariants, other.RelatedInvariants)
	out.ArchitectureRefs = unionStrings(primary.ArchitectureRefs, other.ArchitectureRefs)
	out.ToolFactRefs = unionStrings(primary.ToolFactRefs, other.ToolFactRefs)
	out.RequiredEvidence = unionStrings(primary.RequiredEvidence, other.RequiredEvidence)
	out.MissingLinks = unionStrings(primary.MissingLinks, other.MissingLinks)
	out.CommonDefenses = unionStrings(primary.CommonDefenses, other.CommonDefenses)
	out.CommonFalsePositives = unionStrings(primary.CommonFalsePositives, other.CommonFalsePositives)
	out.CoverageGaps = unionStrings(primary.CoverageGaps, other.CoverageGaps)
	out.CounterEvidence = unionStrings(primary.CounterEvidence, other.CounterEvidence)
	out.ToolFacts = unionStrings(primary.ToolFacts, other.ToolFacts)
	out.GraphFacts = unionStrings(primary.GraphFacts, other.GraphFacts)
	out.ExpectedObligations = unionStrings(primary.ExpectedObligations, other.ExpectedObligations)
	out.OpenQuestions = unionStrings(primary.OpenQuestions, other.OpenQuestions)
	out.Snippets = unionValues(primary.Snippets, other.Snippets)
	out.KnowledgeHints = unionValues(primary.KnowledgeHints, other.KnowledgeHints)
	if len(out.ObservedFlow) == 0 {
		out.ObservedFlow = append([]artifacts.ToolPathStep(nil), other.ObservedFlow...)
	}

	if priorityRank[normalizePriority(other.Priority)] > priorityRank[normalizePriority(primary.Priority)] {
		out.Priority = other.Priority
	}
	return out
}

func unionValues[T any](a, b []T) []T {
	var out []T
	for _, list := range [][]T{a, b} {
		for _, v := range list {
			found := false
			for _, old := range out {
				if reflect.DeepEqual(old, v) {
					found = true
					break
				}
			}
			if !found {
				out = append(out, v)
			}
		}
	}
	return out
}

// unionStrings returns a+b with duplicates removed and first-seen order
// preserved, so a collapse produces the same bytes on every run.
//
// It always allocates a fresh slice. absorb writes onto a struct copy whose
// slice headers still point at the CALLER's backing arrays; appending in
// place would corrupt a pack the caller still holds (see
// TestAbsorb_DoesNotMutateCallersBackingArray). nil is returned when both
// inputs are empty so the pack's omitempty JSON tags still elide the field.
func unionStrings(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// DedupePacks combines repeated targets across passes using SameReviewTarget,
// retaining all evidence. Rich packs sort first so a later max-cases cap does
// not discard grounded investigations in favor of thin candidates.
func DedupePacks(packs []artifacts.CasePack) []artifacts.CasePack {
	var out []artifacts.CasePack
	for _, p := range packs {
		key := targetKey(p)
		if key == "" {
			// Same rule as Merge: a pack with no target files is not a
			// review unit.
			continue
		}
		if at := matchingPack(p, out); at >= 0 {
			// The first occurrence keeps the slot (so ordering stays
			// stable); absorb decides which of the two supplies the
			// identity fields and unions everything else.
			out[at] = absorb(out[at], p)
			continue
		}
		out = append(out, p)
	}

	withPlaybook := make([]artifacts.CasePack, 0, len(out))
	rest := make([]artifacts.CasePack, 0, len(out))
	for _, p := range out {
		if hasInvestigationKnowledge(p) {
			withPlaybook = append(withPlaybook, p)
		} else {
			rest = append(rest, p)
		}
	}
	return append(withPlaybook, rest...)
}

// normalizePriority folds a priority string for lookup in priorityRank only;
// it does not change what gets stored on the pack (absorb still assigns the
// winning pack's Priority verbatim). An unrecognised value — including one that only
// differs from "low"/"medium"/"high" by case or surrounding whitespace, such
// as a model emitting "High" — still ranks 0 and simply cannot win a merge.
func normalizePriority(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}

// Write persists packs as 03_cases/case-%03d.json — the filename shape every
// downstream stage globs for. The planner previously wrote
// <investigation_id>.json here, which no consumer's glob matched, so the
// richest pack in the run was never read by anyone (PR-06, bf9ead6).
func Write(runDir string, packs []artifacts.CasePack) error {
	for i, pack := range packs {
		path := filepath.Join(runfs.CasePacksDir(runDir), fmt.Sprintf("case-%03d.json", i+1))
		if err := runfs.WriteJSON(path, pack); err != nil {
			return fmt.Errorf("write case pack %s: %w", pack.CaseID, err)
		}
	}
	return nil
}

// sanitizeSlug mirrors internal/cases' unexported helper of the same name
// (internal/cases/run.go:298) byte-for-byte in behavior. It is duplicated
// rather than exported from there on purpose: exporting it would make the
// llm path import the legacy case-building package, which this change
// exists to disentangle. A behavioral drift between the two copies would
// make CaseIDs differ in shape between the llm and legacy paths, so any
// edit here must be mirrored there (or vice versa).
func sanitizeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "@", "-", ".", "-", "_", "-", " ", "-")
	value = replacer.Replace(value)
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	return strings.Trim(value, "-")
}

func contractProperties(values []artifacts.CaseInvariantV2) string {
	var keys []string
	seen := map[string]bool{}
	for _, c := range values {
		key := c.Scope.Commit + ":" + contracts.PropertyKey(c)
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	sort.Strings(keys)
	return strings.Join(keys, "\x00")
}
