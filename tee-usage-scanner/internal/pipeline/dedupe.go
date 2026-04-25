package pipeline

import (
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// candidateKey is the dedupe identity for a candidate in the
// multi-sample audit mode. Two candidates collide iff:
//
//   - they cite the EXACT same sorted set of paths, AND
//   - they cite at least one symbol in common (case-sensitive)
//
// The second rule matters because two candidates can target the
// same file but different functions — e.g. `DcapVerifier::new` and
// `DcapVerifier::verify` both live in dcap.rs, and we want to keep
// both as independent audit targets, not merge them into one.
type candidateKey struct {
	pathsJoined string
}

// DedupeCandidates returns a slice containing at most one candidate
// per (paths-set × overlapping-symbols) group, across all input
// bundles. When two candidates collide, the one from the earlier
// bundle (= earlier pass) wins; later duplicates are dropped.
//
// Paths are canonicalised (sorted) before comparison so the dedupe
// is invariant to the order the LLM listed them.
func DedupeCandidates(bundles []*artifacts.EvidenceBundle) []artifacts.Candidate {
	var kept []artifacts.Candidate
	for _, b := range bundles {
		if b == nil {
			continue
		}
		for _, c := range b.Candidates {
			if isDuplicate(c, kept) {
				continue
			}
			kept = append(kept, c)
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

// isDuplicate returns true when c collides with any candidate in
// kept. Collision rules per the package doc.
func isDuplicate(c artifacts.Candidate, kept []artifacts.Candidate) bool {
	cPaths := sortedPaths(c.Paths)
	cSyms := toSet(c.Symbols)
	for _, k := range kept {
		if sortedPaths(k.Paths) != cPaths {
			continue
		}
		// Same path set. Merge only when symbols overlap, or when
		// either side has no symbols (= "whole file" target).
		if len(c.Symbols) == 0 || len(k.Symbols) == 0 {
			return true
		}
		if hasIntersection(cSyms, toSet(k.Symbols)) {
			return true
		}
	}
	return false
}

func sortedPaths(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	cp := make([]string, len(paths))
	copy(cp, paths)
	sort.Strings(cp)
	return strings.Join(cp, "|")
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

func hasIntersection(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}
