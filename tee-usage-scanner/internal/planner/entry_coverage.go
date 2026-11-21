package planner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/projectmap"
)

const (
	entryReadMinimum   = 3
	entryModuleMinimum = 2
	// This is an opening source window, not a claim that the whole function
	// or its callers have been reviewed. One signature line is insufficient.
	entryOpeningLines = 12
)

// EntryCoverageSummary is per planner sample. Known surfaces are neutral
// structural candidates; reading their opening windows does not prove input
// provenance, reachability, or the absence of a vulnerability.
type EntryCoverageSummary struct {
	Capability      string               `json:"capability"`
	Total           int                  `json:"total"`
	Required        int                  `json:"required"`
	Read            int                  `json:"read"`
	ModulesTotal    int                  `json:"modules_total"`
	ModulesRequired int                  `json:"modules_required"`
	ModulesRead     int                  `json:"modules_read"`
	ReadSymbolIDs   []artifacts.SymbolID `json:"read_symbol_ids,omitempty"`
	GateApplies     bool                 `json:"gate_applies"`
}

// WithEntrySurfaces installs only uniquely identified, source-anchored rows.
// Conflicting rows are omitted instead of inventing one location to count.
func (r *ReconState) WithEntrySurfaces(status string, entries []artifacts.EntrySurface) *ReconState {
	r.entryCapability = status
	r.entrySurfaces = map[artifacts.SymbolID]artifacts.EntrySurface{}
	r.entryLinesRead = map[string]map[int]bool{}
	if status != artifacts.CapabilityAvailable && status != artifacts.CapabilityPartial {
		return r
	}
	conflicts := map[artifacts.SymbolID]bool{}
	for _, entry := range entries {
		if entry.SymbolID == "" || !validObservedPath(entry.Path) || entry.StartLine <= 0 || entry.EndLine < entry.StartLine || len(entry.Signals) == 0 {
			continue
		}
		// Modules are derived with the same rule as the rest of the index;
		// a caller-provided label cannot create artificial module spread.
		entry.Module = projectmap.ModuleOf(entry.Path)
		if old, ok := r.entrySurfaces[entry.SymbolID]; ok && (old.Path != entry.Path || old.StartLine != entry.StartLine || old.EndLine != entry.EndLine) {
			conflicts[entry.SymbolID] = true
		}
		r.entrySurfaces[entry.SymbolID] = entry
	}
	for id := range conflicts {
		delete(r.entrySurfaces, id)
	}
	return r
}

// ObserveSourceOutput replaces argument-based read credit in the live loop.
// Pass the excerpt actually exposed by the planner, never the full stored
// blob. Calls to outline/card actions and partial trailing lines earn none.
func (r *ReconState) ObserveSourceOutput(action string, args json.RawMessage, body string, ok bool) {
	path, spans := presentedReadSpans(action, args, body, ok)
	if len(spans) == 0 {
		return
	}
	if r.linesRead == nil {
		r.linesRead = map[string][]lineRange{}
	}
	if r.filesRead == nil {
		r.filesRead = map[string]bool{}
	}
	r.filesRead[path] = true
	r.linesRead[path] = append(r.linesRead[path], spans...)
}

// ObserveEntrySourceOutput is separate from tool execution. The caller must
// invoke it only for source actually present in a dispatched model request.
// This prevents read_file + done in one preplanned response from claiming the
// model inspected the result it had not yet received.
func (r *ReconState) ObserveEntrySourceOutput(action string, args json.RawMessage, body string, ok bool) {
	path, spans := presentedReadSpans(action, args, body, ok)
	if len(spans) == 0 || len(r.entrySurfaces) == 0 {
		return
	}
	if r.entryLinesRead == nil {
		r.entryLinesRead = map[string]map[int]bool{}
	}
	if r.entryLinesRead[path] == nil {
		r.entryLinesRead[path] = map[int]bool{}
	}
	for _, span := range spans {
		for line := span.start; line <= span.end; line++ {
			r.entryLinesRead[path][line] = true
		}
	}
}

// presentedReadSpans accepts the numbered-line protocol from read_file. Its
// arguments supply only the path: requested start/end do not establish what
// survived tool and prompt truncation.
func presentedReadSpans(action string, args json.RawMessage, body string, ok bool) (string, []lineRange) {
	if !ok || action != "read_file" {
		return "", nil
	}
	var input struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(args, &input) != nil || !validObservedPath(input.Path) {
		return "", nil
	}
	// excerpt may append a newline before its marker even when it cut in the
	// middle of a source line. Remove that synthetic newline with the marker.
	if cut := strings.Index(body, "\n... (truncated at "); cut >= 0 {
		body = body[:cut]
	}
	var spans []lineRange
	var current lineRange
	for _, raw := range strings.SplitAfter(body, "\n") {
		if !strings.HasSuffix(raw, "\n") {
			break
		}
		line := strings.TrimSuffix(raw, "\n")
		number, _, valid := strings.Cut(line, ": ")
		n, err := strconv.Atoi(number)
		if !valid || err != nil || n <= 0 {
			break
		}
		if current.start == 0 {
			current = lineRange{n, n}
			continue
		}
		if n != current.end+1 {
			break
		}
		current.end = n
	}
	if current.start > 0 {
		spans = append(spans, current)
	}
	return input.Path, spans
}

func (r *ReconState) EntryCoverage() EntryCoverageSummary {
	summary := EntryCoverageSummary{Capability: r.entryCapability, Total: len(r.entrySurfaces), GateApplies: r.leadsOpened == 0 && !r.skipped && len(r.entrySurfaces) > 0}
	if summary.Capability == "" {
		summary.Capability = artifacts.CapabilityUnavailable
	}
	modules := map[string]bool{}
	readModules := map[string]bool{}
	for id, entry := range r.entrySurfaces {
		modules[entry.Module] = true
		end := min(entry.EndLine, entry.StartLine+entryOpeningLines-1)
		read := true
		for line := entry.StartLine; line <= end; line++ {
			if !r.entryLinesRead[entry.Path][line] {
				read = false
				break
			}
		}
		if read {
			summary.ReadSymbolIDs = append(summary.ReadSymbolIDs, id)
			readModules[entry.Module] = true
		}
	}
	sort.Slice(summary.ReadSymbolIDs, func(i, j int) bool { return summary.ReadSymbolIDs[i] < summary.ReadSymbolIDs[j] })
	summary.Required = min(entryReadMinimum, summary.Total)
	summary.Read = len(summary.ReadSymbolIDs)
	summary.ModulesTotal = len(modules)
	summary.ModulesRequired = min(entryModuleMinimum, len(modules))
	summary.ModulesRead = len(readModules)
	return summary
}

// EntryCoverageGaps describes raw unsampled entry windows, even after a lead
// has opened. DoneUnmet decides whether these gaps gate a zero-lead result.
func (r *ReconState) EntryCoverageGaps() []string {
	s := r.EntryCoverage()
	if s.Total == 0 {
		return nil
	}
	var gaps []string
	if s.Read < s.Required {
		gaps = append(gaps, fmt.Sprintf("read opening source windows for %d more entry candidate(s) — %d of %d required; use list_entry_surfaces then read_file across each definition's first %d lines (or its whole definition if shorter)", s.Required-s.Read, s.Read, s.Required, entryOpeningLines))
	}
	if s.ModulesRead < s.ModulesRequired {
		gaps = append(gaps, fmt.Sprintf("read entry source windows from %d more module(s) — %d of %d required", s.ModulesRequired-s.ModulesRead, s.ModulesRead, s.ModulesRequired))
	}
	return gaps
}

func (r *ReconState) entryCoverageIncomplete() bool {
	return r.leadsOpened == 0 && !r.skipped && len(r.EntryCoverageGaps()) > 0
}

// DoneUnmet is intentionally independent of AllowLead. Source evidence may
// justify opening a lead early, while a zero-lead conclusion needs both the
// normal reconnaissance floor and the available entry-source sample.
func (r *ReconState) DoneUnmet() string {
	if r.leadsOpened > 0 || r.skipped {
		return ""
	}
	var gaps []string
	if !r.skipped {
		gaps = append(gaps, r.unmet()...)
	}
	gaps = append(gaps, r.EntryCoverageGaps()...)
	if len(gaps) == 0 {
		return ""
	}
	return "  - " + strings.Join(gaps, "\n  - ")
}

func (r *ReconState) DoneCoverageIncomplete() bool { return r.DoneUnmet() != "" }
