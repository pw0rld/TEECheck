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
		Priority:      cand.Priority,
		TargetFiles:   append([]string{}, cand.Paths...),
		TargetSymbols: append([]string{}, cand.Symbols...),
		WhySelected:   append([]string{}, cand.WhySelected...),
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
// packs into the final list to persist.
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

// absorb folds a thin pack into the rich pack that shares its target set.
// The rich pack is the base — it carries the playbook knowledge, which is the
// whole reason this pipe exists.
func absorb(base, extra artifacts.CasePack) artifacts.CasePack {
	seen := map[string]bool{}
	for _, w := range base.WhySelected {
		seen[w] = true
	}
	for _, w := range extra.WhySelected {
		if !seen[w] {
			seen[w] = true
			base.WhySelected = append(base.WhySelected, w)
		}
	}
	if priorityRank[extra.Priority] > priorityRank[base.Priority] {
		base.Priority = extra.Priority
	}
	return base
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
