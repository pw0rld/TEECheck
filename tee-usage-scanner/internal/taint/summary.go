package taint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
)

type summaryPath struct {
	Hops        []string `json:"hops"`
	OmittedHops int      `json:"omitted_hops,omitempty"`
}
type summaryCluster struct {
	SinkFunc string `json:"sink_func"`
	SinkFile string `json:"sink_file"`
	Count    int    `json:"count"`
}
type summary struct {
	FactRef           string           `json:"fact_ref"`
	ToolFactRef       string           `json:"tool_fact_ref"`
	FactID            string           `json:"fact_id"`
	Operation         string           `json:"operation"`
	Status            string           `json:"status"`
	TotalPaths        int              `json:"total_paths"`
	ReturnedPaths     int              `json:"returned_paths"`
	Truncated         bool             `json:"truncated"`
	ElapsedMS         int64            `json:"elapsed_ms"`
	BarriersApplied   []string         `json:"barriers_applied"`
	Paths             []summaryPath    `json:"paths"`
	RemainingClusters []summaryCluster `json:"remaining_clusters,omitempty"`
	OmittedClusters   int              `json:"omitted_clusters,omitempty"`
	CoverageNote      string           `json:"coverage_note"`
	CoverageGaps      []string         `json:"coverage_gaps,omitempty"`
	Error             string           `json:"error,omitempty"`
}

// RenderSummary returns only bounded views. The persisted ToolFact retains all
// CodeQL-emitted witnesses, including the unrendered tail of every path.
func RenderSummary(fact artifacts.ToolFact, path string, maxPaths, maxHops int) string {
	if maxPaths <= 0 {
		maxPaths = 5
	}
	if maxPaths > 10 {
		maxPaths = 10
	}
	if maxHops <= 0 {
		maxHops = 12
	}
	if maxHops > 20 {
		maxHops = 20
	}
	var meta Result
	_ = json.Unmarshal(fact.Result, &meta)
	if meta.TotalPaths < len(fact.Paths) {
		meta.TotalPaths = len(fact.Paths)
	}
	note := "Counts and shortest-first ordering describe the CodeQL-emitted path witnesses, not all possible paths or globally shortest program paths. Barrier functions are syntactic filters, not verified guards."
	if meta.TotalPaths == 0 && fact.Status == "success" {
		note = ZeroPathNotice + " " + note
	} else if fact.Status != "success" {
		note = "The query did not produce complete usable path evidence; do not interpret failure as an empty successful search or as safety. " + note
	}
	view := summary{FactRef: path, ToolFactRef: path, FactID: fact.FactID, Operation: fact.Operation, Status: fact.Status, TotalPaths: meta.TotalPaths, ElapsedMS: meta.ElapsedMS, BarriersApplied: meta.BarriersApplied, Paths: []summaryPath{}, CoverageNote: note, Error: compactText(fact.Error, 1000)}
	for _, gap := range fact.CoverageGaps[:min(8, len(fact.CoverageGaps))] {
		view.CoverageGaps = append(view.CoverageGaps, compactText(gap, 1024))
	}
	if len(fact.CoverageGaps) > 8 {
		view.CoverageNote += fmt.Sprintf(" %d additional coverage notes are retained in the artifact.", len(fact.CoverageGaps)-8)
	}
	for _, steps := range fact.Paths[:min(maxPaths, len(fact.Paths))] {
		p := summaryPath{Hops: []string{}, OmittedHops: max(0, len(steps)-maxHops)}
		for i, step := range steps[:min(maxHops, len(steps))] {
			fn := step.Location.Symbol
			if fn == "" {
				fn = "(function unavailable)"
			}
			p.Hops = append(p.Hops, fmt.Sprintf("[%d] %s:%d %s :: %s", i, step.Location.Path, step.Location.StartLine, compactText(fn, 256), compactText(step.Message, 240)))
		}
		view.Paths = append(view.Paths, p)
	}
	// Whole-path removal preserves valid JSON and avoids inventing a terminal
	// node by cutting a hop mid-record. Count summaries cover omitted paths.
	for {
		view.ReturnedPaths = len(view.Paths)
		view.Truncated = len(view.Paths) < view.TotalPaths
		for _, p := range view.Paths {
			view.Truncated = view.Truncated || p.OmittedHops > 0
		}
		view.RemainingClusters = clusters(fact.Paths[len(view.Paths):])
		view.OmittedClusters = 0
		for {
			body, _ := json.Marshal(view)
			if len(body) <= observationlimits.MaxBytes {
				return string(body)
			}
			if len(view.RemainingClusters) > 0 {
				view.RemainingClusters = view.RemainingClusters[:len(view.RemainingClusters)-1]
				view.OmittedClusters++
				view.Truncated = true
				continue
			}
			break
		}
		if len(view.Paths) > 0 {
			view.Paths = view.Paths[:len(view.Paths)-1]
			continue
		}
		// Runtime-generated identifiers are bounded, but callers may render an
		// external artifact; the fallback still states truncation and identity.
		view.FactRef = compactText(path, 4096)
		view.ToolFactRef = view.FactRef
		view.FactID = compactText(fact.FactID, 512)
		view.Truncated = true
		body, _ := json.Marshal(view)
		if len(body) <= observationlimits.MaxBytes {
			return string(body)
		}
		return `{"status":"unresolved","truncated":true,"coverage_note":"Tool fact metadata exceeds observation limit; inspect the persisted artifact. This is not proof of safety."}`
	}
}

func clusters(paths [][]artifacts.ToolPathStep) []summaryCluster {
	counts := map[string]summaryCluster{}
	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		sink := path[len(path)-1].Location
		key := sink.Symbol + "\x00" + sink.Path
		c := counts[key]
		c.SinkFunc = sink.Symbol
		c.SinkFile = sink.Path
		c.Count++
		counts[key] = c
	}
	var out []summaryCluster
	for _, c := range counts {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SinkFunc != out[j].SinkFunc {
			return out[i].SinkFunc < out[j].SinkFunc
		}
		return out[i].SinkFile < out[j].SinkFile
	})
	return out
}

func compactText(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}
