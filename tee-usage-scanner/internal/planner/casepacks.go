package planner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
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

// targetKey is the identity a merge compares: the sorted, deduplicated set of
// target files. Two packs merge ONLY when this is identical.
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

// Merge combines investigation-derived (rich) and candidate-derived (thin)
// packs from ONE planner pass into the list that pass returns.
//
// Merge itself never collapses two rich packs: the byKey map below is filled
// from `rich` first, and a second rich pack with the same key simply
// overwrites the map entry and is appended as its own pack. Only thin packs
// are folded in, into whichever rich pack currently owns the key. That is a
// property of Merge alone, not of the pipeline: internal/pipeline/run.go runs
// DedupePacks over the union of every pass afterwards, and DedupePacks DOES
// collapse rich pairs. absorb unions the knowledge-bearing fields precisely
// so that collapse is lossless — see its doc comment.
//
// Two rules, both deliberate:
//
//   - Packs merge ONLY when their target-file sets are exactly equal. A
//     partial overlap does NOT merge. A redundant case costs one extra Expert
//     call, which is visible and measurable; a wrong merge silently destroys
//     a finding. Across the 29 measured L3 runs, 14 pairs were exactly equal
//     and partial overlap never once occurred — so this rule currently costs
//     nothing.
//   - A pack with no target files is dropped. It comes from an investigation
//     whose roles were all missing, i.e. a record of "I looked and located
//     nothing". That record stays in 03_investigations/; it is the next
//     investigative task (prompt.go's CRITICAL RULES), not a review unit.
//
// Rich packs sort before thin ones so numbering is stable across runs.
func Merge(rich, thin []artifacts.CasePack) []artifacts.CasePack {
	var out []artifacts.CasePack
	byKey := map[string]int{}

	for _, p := range rich {
		key := targetKey(p)
		if key == "" {
			continue
		}
		byKey[key] = len(out)
		out = append(out, p)
	}
	for _, p := range thin {
		key := targetKey(p)
		if key == "" {
			continue
		}
		if at, ok := byKey[key]; ok {
			out[at] = absorb(out[at], p)
			continue
		}
		byKey[key] = len(out)
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

// absorb collapses two packs that name the same target-file set into one.
//
// Which side supplies the scalar identity is decided by RICHNESS, not by
// argument position: whichever pack carries investigation-derived knowledge
// becomes the primary. When both do (DedupePacks routes rich+rich here) or
// neither does, base stays primary, so the callers' first-occurrence-wins
// ordering is preserved and the result stays deterministic.
//
// CaseID and Category are taken from the primary, and from the SAME pack, on
// purpose:
//
//   - A rich pack's CaseID is its InvestigationID — the only key tying the
//     persisted pack back to its 03_investigations/<id>.json record. A thin
//     pack's CaseID is a positional "...:candidate:NNN" slug that references
//     nothing. Letting the thin one win would orphan the record.
//   - A rich pack's Category is the investigation's classification
//     (standard/variant/composition/catalog_gap, always non-empty — see
//     internal/investigations.classify); a thin pack's is derived from the
//     candidate kind. Taking both fields from one pack keeps the persisted
//     pack describing one coherent origin rather than a chimera whose
//     Category contradicts its CaseID.
//
// Every knowledge-bearing slice is UNIONED — primary's entries first, then
// the other side's, deduplicated with first-seen order preserved. Taking only
// the primary's would silently destroy the other pack's playbook knowledge:
// two investigations that resolved to the same file are two different TWE
// scenarios about it, and dropping either one's common_defenses /
// common_false_positives puts the run back where PR-06 started — knowledge
// produced and then discarded before any agent could read it.
//
// Fields deliberately NOT unioned: SchemaVersion/HotspotID/Focus are run-wide
// constants taken from the primary; ObservedFlow is an ORDERED path rather
// than a set, so concatenating the two sides' steps would present downstream
// agents with a numbered sequence no tool ever traced — the primary's path is
// kept whole and the other side's stays in its own 03_investigations/<id>.json
// record (see TestAbsorb_KeepsOneCoherentObservedFlow); TargetFiles are equal
// as sets by the caller's own merge rule; ExpectedObligations/OpenQuestions/ToolFacts/
// GraphFacts/Snippets/KnowledgeHints are never populated on this path — only
// internal/cases (legacy) and the post-planner enrichment stage write them,
// and neither feeds packs through Merge or DedupePacks.
func absorb(base, extra artifacts.CasePack) artifacts.CasePack {
	primary, other := base, extra
	if !hasInvestigationKnowledge(base) && hasInvestigationKnowledge(extra) {
		primary, other = extra, base
	}

	out := primary
	out.WhySelected = unionStrings(primary.WhySelected, other.WhySelected)
	out.TargetSymbols = unionStrings(primary.TargetSymbols, other.TargetSymbols)
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

	if priorityRank[normalizePriority(other.Priority)] > priorityRank[normalizePriority(primary.Priority)] {
		out.Priority = other.Priority
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

// DedupePacks collapses packs that name the same set of target files. It
// receives the union of every --samples pass with no pass provenance
// attached, so it CANNOT tell "two investigations within one pass" from "the
// same finding seen in two passes" and does not try: every same-target-set
// pair collapses, rich pairs included.
//
// That is safe only because absorb unions the knowledge-bearing fields
// instead of keeping the first pack's. When absorb took every field but
// WhySelected/Priority from its base, this unconditional collapse silently
// destroyed one full investigation's playbook knowledge per collision — with
// --samples 1 as well, since two done.investigations entries whose
// filled_roles resolve to the same file collide inside a single pass.
//
// Packs carrying investigation-derived knowledge (hasInvestigationKnowledge)
// are returned first, preserving relative order within each group, so that a
// --max-cases truncation drops the least informative packs rather than an
// arbitrary slice.
func DedupePacks(packs []artifacts.CasePack) []artifacts.CasePack {
	var out []artifacts.CasePack
	byKey := map[string]int{}
	for _, p := range packs {
		key := targetKey(p)
		if key == "" {
			// Same rule as Merge: a pack with no target files is not a
			// review unit.
			continue
		}
		if at, ok := byKey[key]; ok {
			// The first occurrence keeps the slot (so ordering stays
			// stable); absorb decides which of the two supplies the
			// identity fields and unions everything else.
			out[at] = absorb(out[at], p)
			continue
		}
		byKey[key] = len(out)
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
