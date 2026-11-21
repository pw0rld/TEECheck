package repoindex

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// decodeEntrySurfaces binds each row to a symbol already emitted by Symbols.ql.
// A malformed row or an unknown definition is a coverage loss, never a new
// invented symbol. The definition-only rows provide ranges for graph signals.
func decodeEntrySurfaces(rows [][]string, facts artifacts.RepoFacts) ([]artifacts.EntrySurface, []string) {
	known := make(map[artifacts.SymbolID]artifacts.Symbol, len(facts.Symbols))
	for _, s := range facts.Symbols {
		known[s.SymbolID] = s
	}
	byID := map[artifacts.SymbolID]*artifacts.EntrySurface{}
	ambiguous := map[artifacts.SymbolID]bool{}
	var invalid int
	for _, row := range rows {
		if len(row) != 11 {
			invalid++
			continue
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(row[2]))
		end, err2 := strconv.Atoi(strings.TrimSpace(row[3]))
		evidenceStart, err3 := strconv.Atoi(strings.TrimSpace(row[8]))
		evidenceEnd, err4 := strconv.Atoi(strings.TrimSpace(row[9]))
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || start < 1 || end < start || evidenceStart < 1 || evidenceEnd < evidenceStart || !entryRelativePath(row[1]) || !entryRelativePath(row[7]) {
			invalid++
			continue
		}
		id := symbolIDOf(row[0], row[1], row[2], row[4])
		if ambiguous[id] {
			invalid++
			continue
		}
		symbol, ok := known[id]
		if !ok {
			invalid++
			continue
		}
		signal := strings.TrimSpace(row[6])
		switch signal {
		case "definition", artifacts.EntrySignalExternalLinkage, artifacts.EntrySignalGlobalFunctionPointerInitializer, artifacts.EntrySignalBufferLengthParameters:
		default:
			invalid++
			continue
		}
		surface := byID[id]
		if surface == nil {
			surface = &artifacts.EntrySurface{SymbolID: id, Name: symbol.Name, Path: symbol.File, Module: symbol.Module, StartLine: start, EndLine: end}
			byID[id] = surface
		} else if surface.EndLine != end {
			// Different extraction units disagree about the same definition's
			// extent. Keep a diagnostic and do not claim a complete range.
			invalid++
			delete(byID, id)
			ambiguous[id] = true
			continue
		}
		if signal == "definition" {
			continue
		}
		addEntrySignal(surface, signal, artifacts.EntrySurfaceEvidence{Signal: signal, Path: strings.TrimSpace(row[7]), StartLine: evidenceStart, EndLine: evidenceEnd, Detail: strings.TrimSpace(row[10])})
	}
	callers := map[artifacts.SymbolID]bool{}
	for _, e := range facts.CallEdges {
		callers[e.CalleeID] = true
	}
	graphUsable := facts.Capabilities.DirectCalls == artifacts.CapabilityAvailable || facts.Capabilities.DirectCalls == artifacts.CapabilityPartial
	var out []artifacts.EntrySurface
	for id, surface := range byID {
		if graphUsable && !callers[id] {
			addEntrySignal(surface, artifacts.EntrySignalNoResolvedInternalCallers, artifacts.EntrySurfaceEvidence{
				Signal: artifacts.EntrySignalNoResolvedInternalCallers, Path: surface.Path, StartLine: surface.StartLine, EndLine: surface.EndLine,
				Detail: "no caller in the direct resolved in-tree call graph; indirect, external and unresolved callers are not excluded",
			})
		}
		if len(surface.Signals) == 0 {
			continue
		}
		sort.Strings(surface.Signals)
		sort.Slice(surface.EvidenceRefs, func(i, j int) bool {
			a, b := surface.EvidenceRefs[i], surface.EvidenceRefs[j]
			if a.Signal != b.Signal {
				return a.Signal < b.Signal
			}
			if a.Path != b.Path {
				return a.Path < b.Path
			}
			if a.StartLine != b.StartLine {
				return a.StartLine < b.StartLine
			}
			if a.EndLine != b.EndLine {
				return a.EndLine < b.EndLine
			}
			return a.Detail < b.Detail
		})
		out = append(out, *surface)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SymbolID < out[j].SymbolID })
	var notes []string
	if invalid > 0 {
		notes = append(notes, fmt.Sprintf("%d malformed, inconsistent or unbound entry-surface rows omitted", invalid))
	}
	if len(byID) < len(known) {
		notes = append(notes, fmt.Sprintf("entry-surface definition ranges available for %d of %d indexed definitions", len(byID), len(known)))
	}
	if !graphUsable {
		notes = append(notes, "caller absence signal unavailable because direct-call coverage is unavailable")
	}
	return out, notes
}

func entryRelativePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean == path && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func addEntrySignal(surface *artifacts.EntrySurface, signal string, evidence artifacts.EntrySurfaceEvidence) {
	hasSignal := false
	for _, old := range surface.Signals {
		if old == signal {
			hasSignal = true
			break
		}
	}
	if !hasSignal {
		surface.Signals = append(surface.Signals, signal)
	}
	for _, old := range surface.EvidenceRefs {
		if old == evidence {
			return
		}
	}
	surface.EvidenceRefs = append(surface.EvidenceRefs, evidence)
}
