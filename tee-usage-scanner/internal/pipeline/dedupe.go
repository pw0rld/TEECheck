package pipeline

import (
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

// MergeEvidenceBundles produces the canonical multi-sample bundle without
// making pass 1's budget and termination look like aggregate values.
func MergeEvidenceBundles(bundles []*artifacts.EvidenceBundle) artifacts.EvidenceBundle {
	if len(bundles) == 0 {
		return artifacts.EvidenceBundle{}
	}
	merged := *bundles[0]
	merged.Candidates = DedupeCandidates(bundles)
	merged.Errors = nil
	merged.PlannerMeta = artifacts.PlannerMeta{
		TerminationReason: bundles[0].PlannerMeta.TerminationReason,
		PassCount:         len(bundles),
		Passes:            make([]artifacts.PlannerPassMeta, 0, len(bundles)),
	}
	if len(bundles) > 1 {
		merged.PlannerMeta.TerminationReason = "multi_sample"
	}
	for index, bundle := range bundles {
		meta := bundle.PlannerMeta
		merged.PlannerMeta.RoundsUsed += meta.RoundsUsed
		merged.PlannerMeta.RoundsBudget += meta.RoundsBudget
		merged.PlannerMeta.TokensUsed += meta.TokensUsed
		merged.PlannerMeta.WallClockMs += meta.WallClockMs
		merged.PlannerMeta.Truncated = merged.PlannerMeta.Truncated || meta.Truncated
		merged.PlannerMeta.Passes = append(merged.PlannerMeta.Passes, artifacts.PlannerPassMeta{
			SampleIndex:       index,
			RoundsUsed:        meta.RoundsUsed,
			RoundsBudget:      meta.RoundsBudget,
			TokensUsed:        meta.TokensUsed,
			WallClockMs:       meta.WallClockMs,
			TerminationReason: meta.TerminationReason,
			Truncated:         meta.Truncated,
		})
		merged.Errors = append(merged.Errors, bundle.Errors...)
	}
	return merged
}

// DedupeCandidates uses the same conservative target identity as Case Packs.
// Expanded evidence windows are merged without discarding paths or reasons;
// distinct symbols or categories remain separate review candidates.
func DedupeCandidates(bundles []*artifacts.EvidenceBundle) []artifacts.Candidate {
	var kept []artifacts.Candidate
	for _, b := range bundles {
		if b == nil {
			continue
		}
		for _, c := range b.Candidates {
			if at := duplicateCandidate(c, kept); at >= 0 {
				kept[at] = mergeCandidate(kept[at], c)
			} else {
				kept = append(kept, c)
			}
		}
	}
	return kept
}

// AvoidList renders the kept-so-far candidates into the
// "file::symbol" lines the planner prompt expects as its avoid-list.
// Used between passes to tell the next planner pass what it should
// NOT re-pick.
func AvoidList(candidates []artifacts.Candidate) []string {
	var out []string
	for _, c := range candidates {
		if len(c.Symbols) == 0 {
			for _, p := range c.Paths {
				out = append(out, p)
			}
			continue
		}
		for _, p := range c.Paths {
			for _, s := range c.Symbols {
				out = append(out, p+"::"+s)
			}
		}
	}
	return out
}

func duplicateCandidate(c artifacts.Candidate, kept []artifacts.Candidate) int {
	asPack := func(v artifacts.Candidate) artifacts.CasePack {
		return artifacts.CasePack{TargetFiles: v.Paths, TargetSymbols: v.Symbols, Category: v.Kind}
	}
	for i, k := range kept {
		if planner.SameReviewTarget(asPack(c), asPack(k)) {
			return i
		}
	}
	return -1
}

func mergeCandidate(base, extra artifacts.Candidate) artifacts.Candidate {
	base.Paths = unionCandidateValues(base.Paths, extra.Paths)
	base.Symbols = unionCandidateValues(base.Symbols, extra.Symbols)
	base.WhySelected = unionCandidateValues(base.WhySelected, extra.WhySelected)
	base.EvidenceRefs = unionCandidateValues(base.EvidenceRefs, extra.EvidenceRefs)
	if extra.Confidence > base.Confidence {
		base.Confidence = extra.Confidence
	}
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	if rank[strings.ToLower(strings.TrimSpace(extra.Priority))] > rank[strings.ToLower(strings.TrimSpace(base.Priority))] {
		base.Priority = extra.Priority
	}
	if base.Kind == "" {
		base.Kind = extra.Kind
	}
	if base.SinkCategory == "" {
		base.SinkCategory = extra.SinkCategory
	}
	return base
}

func unionCandidateValues(a, b []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if !seen[value] {
				out = append(out, value)
				seen[value] = true
			}
		}
	}
	return out
}
