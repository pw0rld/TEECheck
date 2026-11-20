package arbiter

import (
	"sort"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
)

// findingLocations derives a finding's structured (file, line) positions from
// the case's anchored ToolFacts.
//
// FindingItem.Locations exists so a consumer — the benchmark scorer — can
// match on a line without parsing one out of prose. Nothing ever assigned it.
// Every finding this package has emitted carries Files (paths only) and an
// absent Locations key, while the ToolFact sitting in the same case names the
// exact line: on run 44362-vuln-p9 the fact said
// core/crypto/signed_hdr.c:262 and the finding said core/crypto/signed_hdr.c.
//
// The source is deliberately the ToolFact and not the model's output. A line
// number is the one part of a finding that is either right or wrong with no
// interpretation in between, and the fact layer computed it deterministically;
// asking the LLM to restate it would put a challengeable assessment where an
// immutable fact already exists (§ three-tier evidence). Facts with no
// locations — a query that ran and matched nothing — contribute nothing, which
// is why a fixed revision yields no locations rather than a wrong one.
//
// Both a finding's primary location and the sites it names are included: on
// TWE-STATE-001 the producer and the rollback authority are in different
// files, and a scorer matching only the primary would miss the authority half
// of the weakness.
func findingLocations(caseCtx caseContext) []artifacts.FindingLocation {
	seen := make(map[struct {
		Path string
		Line int
	}]int)
	var out []artifacts.FindingLocation

	add := func(l artifacts.ToolLocation) {
		if l.Path == "" || l.StartLine <= 0 {
			return
		}
		fl := artifacts.FindingLocation{Path: l.Path, StartLine: l.StartLine, Symbol: l.Symbol}
		key := struct {
			Path string
			Line int
		}{l.Path, l.StartLine}
		if i, ok := seen[key]; ok {
			if out[i].Symbol == "" {
				out[i].Symbol = l.Symbol
			}
			return
		}
		seen[key] = len(out)
		out = append(out, fl)
	}

	for _, f := range caseCtx.toolFacts {
		for _, l := range f.Locations {
			add(l)
		}
		for _, fi := range f.Findings {
			add(fi.Location)
			for _, r := range fi.Related {
				add(r)
			}
		}
	}

	// Stable order: two runs over the same facts must produce byte-identical
	// findings, or a vulnerable/fixed differential shows spurious changes.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].StartLine < out[j].StartLine
	})
	return out
}

// reviewedFindingLocations also preserves validated byte-citation positions
// for cases that have no CodeQL finding. Unanchored or stale expert claims are
// deliberately excluded; only the verifier's confirmed resolved citations or
// expert citations that it actually revalidated can supply an extra location.
func reviewedFindingLocations(ctx caseContext, memo artifacts.VerificationMemo) []artifacts.FindingLocation {
	locations := findingLocations(ctx)
	seen := make(map[struct {
		path string
		line int
	}]bool)
	for _, l := range locations {
		seen[struct {
			path string
			line int
		}{l.Path, l.StartLine}] = true
	}
	add := func(c citations.CitedBytes) {
		if !c.Resolved() || !c.Valid() {
			return
		}
		key := struct {
			path string
			line int
		}{c.File, c.StartLine}
		if !seen[key] {
			locations = append(locations, artifacts.FindingLocation{Path: c.File, StartLine: c.StartLine})
			seen[key] = true
		}
	}
	for _, f := range memo.ConfirmedCitedFacts {
		for _, c := range f.Cited {
			add(c)
		}
	}
	for _, f := range memo.ExpertCitationValidation {
		if f.Status == citations.StatusValid {
			for _, c := range f.Cited {
				add(c)
			}
		}
	}
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Path != locations[j].Path {
			return locations[i].Path < locations[j].Path
		}
		return locations[i].StartLine < locations[j].StartLine
	})
	return locations
}
