package artifacts

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// The full witness set stays in the hash-bound artifact. All review roles get
// the same bounded view, without importing the query executor into artifacts.
func formatTaintFact(f ToolFact) string {
	const maxBytes = 8192
	var meta struct {
		TotalPaths       int      `json:"total_paths"`
		BarriersApplied  []string `json:"barriers_applied"`
		RankedCandidates []struct {
			PathIndex *int `json:"path_index"`
		} `json:"ranked_candidates"`
	}
	_ = json.Unmarshal(f.Result, &meta)
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s status=%s; persisted witness paths=%d; content_sha256=%s\n", reviewText(f.FactID, 160), f.Operation, reviewText(f.Status, 32), meta.TotalPaths, reviewText(f.ContentSHA256, 64))
	b.WriteString("Static may-flow evidence only. Zero paths, or paths removed by a configured barrier, do NOT prove safety. Counts cover CodeQL-emitted witnesses, not every possible path.\n")
	if len(meta.BarriersApplied) > 0 {
		fmt.Fprintf(&b, "Syntactic call-result filters (not verified guards): %s\n", reviewText(strings.Join(meta.BarriersApplied, ", "), 512))
	}
	if f.Error != "" {
		fmt.Fprintf(&b, "Tool error: %s\n", reviewText(f.Error, 512))
	}
	shown := 0
	maxNodes := 12
	if f.Operation == TaintPrescanOperation {
		maxNodes = 10
	}
	paths := f.Paths
	if f.Operation == TaintPrescanOperation && len(meta.RankedCandidates) > 0 {
		paths = nil
		seen := map[int]bool{}
		for _, candidate := range meta.RankedCandidates {
			if candidate.PathIndex == nil {
				continue
			}
			index := *candidate.PathIndex
			if index < 0 || index >= len(f.Paths) || seen[index] {
				continue
			}
			seen[index] = true
			paths = append(paths, f.Paths[index])
		}
	}
	for i, path := range paths {
		if i >= 5 {
			break
		}
		var p strings.Builder
		fmt.Fprintf(&p, "Witness %d (%d nodes):\n", i+1, len(path))
		for j, node := range path {
			if j >= maxNodes {
				fmt.Fprintf(&p, "  ... %d additional nodes in artifact\n", len(path)-maxNodes)
				break
			}
			fmt.Fprintf(&p, "  [%d] %s:%d %s :: %s\n", j, reviewText(node.Location.Path, 300), node.Location.StartLine, reviewText(node.Location.Symbol, 120), reviewText(node.Message, 180))
		}
		if b.Len()+p.Len() > maxBytes-1024 {
			break
		}
		b.WriteString(p.String())
		shown++
	}
	if shown < len(f.Paths) {
		fmt.Fprintf(&b, "%d other witness paths remain in the referenced artifact.\n", len(f.Paths)-shown)
	}
	for _, gap := range f.CoverageGaps {
		line := "Coverage: " + reviewText(gap, 400) + "\n"
		if b.Len()+len(line) > maxBytes {
			break
		}
		b.WriteString(line)
	}
	return b.String()
}

func reviewText(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}
