package arbiter

import (
	"sort"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
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
	seen := make(map[artifacts.FindingLocation]bool)
	var out []artifacts.FindingLocation

	add := func(l artifacts.ToolLocation) {
		if l.Path == "" || l.StartLine <= 0 {
			return
		}
		fl := artifacts.FindingLocation{Path: l.Path, StartLine: l.StartLine}
		if seen[fl] {
			return
		}
		seen[fl] = true
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
