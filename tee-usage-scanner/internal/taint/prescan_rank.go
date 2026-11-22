package taint

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

var prescanMemoryCalls = map[string]bool{
	"memcpy": true, "memmove": true, "memset": true, "memcmp": true, "buf_compare_ct": true,
	"copy_from_user": true, "copy_to_user": true, "bb_memdup_user": true, "malloc": true, "calloc": true, "realloc": true,
}

func prescanSymbol(facts *artifacts.RepoFacts, loc artifacts.ToolLocation) string {
	if facts == nil {
		return ""
	}
	// Entry surfaces retain definition end lines; the plain symbol index does
	// not. Never invent a containing function from the nearest preceding row.
	for _, entry := range facts.EntrySurfaces {
		if entry.Path == loc.Path && entry.StartLine <= loc.StartLine && entry.EndLine >= loc.StartLine {
			return entry.Name
		}
	}
	for _, symbol := range facts.Symbols {
		if symbol.File == loc.Path && symbol.StartLine == loc.StartLine {
			return symbol.Name
		}
	}
	return ""
}

func prescanMetadata(message string) (signal, kind, sink string) {
	const prefix = "teecheck_entry_taint "
	if !strings.HasPrefix(message, prefix) {
		return "", "", ""
	}
	values := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(message, prefix), ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			values[k] = v
		}
	}
	if values["source_signal"] == artifacts.EntrySignalGlobalFunctionPointerInitializer || values["source_signal"] == artifacts.EntrySignalBufferLengthParameters {
		signal = values["source_signal"]
	}
	switch values["sink_kind"] {
	case "array_index", "pointer_deref", "memory_call":
		kind = values["sink_kind"]
	}
	if kind == "memory_call" && prescanMemoryCalls[values["sink_func"]] {
		sink = values["sink_func"]
	}
	return
}

func prescanCandidate(path []artifacts.ToolPathStep, index int, message string, facts *artifacts.RepoFacts) PrescanCandidate {
	source, sink := path[0].Location, path[len(path)-1].Location
	signal, kind, sinkFunc := prescanMetadata(message)
	if signal == "" && facts != nil {
		for _, entry := range facts.EntrySurfaces {
			if entry.Path != source.Path || source.StartLine < entry.StartLine || source.StartLine > entry.EndLine {
				continue
			}
			for _, s := range entry.Signals {
				if s == artifacts.EntrySignalGlobalFunctionPointerInitializer {
					signal = s
					break
				}
				if s == artifacts.EntrySignalBufferLengthParameters {
					signal = s
				}
			}
		}
	}
	sourceFunc := source.Symbol
	if sourceFunc == "" {
		sourceFunc = "(function unavailable)"
	}
	if sinkFunc == "" {
		sinkFunc = kind
	}
	if sinkFunc == "" {
		sinkFunc = sink.Symbol
	}
	if sinkFunc == "" {
		sinkFunc = "(sink unavailable)"
	}
	c := PrescanCandidate{PathIndex: index, SourceFunc: sourceFunc, SinkFunc: sinkFunc, SourceSignal: signal, SinkKind: kind, Source: source, Sink: sink, Hops: len(path)}
	if source.Path != sink.Path {
		c.Score += 40
	}
	functions := map[string]bool{}
	for _, step := range path {
		if step.Location.Symbol != "" {
			functions[step.Location.Symbol] = true
		}
	}
	if len(functions) > 1 {
		c.Score += 20
	}
	if signal == artifacts.EntrySignalGlobalFunctionPointerInitializer {
		c.Score += 40
	}
	if prescanMemoryCalls[sinkFunc] {
		c.Score += 20
	}
	if source.Path == sink.Path && kind == "array_index" && prescanLowLevelPath(sink.Path) {
		c.Score -= 200
	}
	return c
}

func prescanLowLevelPath(path string) bool {
	path = "/" + strings.ToLower(strings.Trim(path, "/")) + "/"
	for _, part := range []string{"/ciphers/", "/mbedtls/", "/libtomcrypt/", "/libmpa/", "/libfdt/"} {
		if strings.Contains(path, part) {
			return true
		}
	}
	return false
}

func prescanSourceKey(c PrescanCandidate) string {
	key := c.SourceFunc + "\x00" + c.Source.Path
	if c.SourceFunc == "(function unavailable)" {
		key += "\x00" + strconv.Itoa(c.Source.StartLine)
	}
	return key
}

func candidateKey(c PrescanCandidate) string {
	return prescanSourceKey(c) + "\x00" + c.SinkFunc + "\x00" + c.Sink.Path + "\x00" + strconv.Itoa(c.Sink.StartLine)
}

// RankPrescanCandidates collapses equivalent destinations to their shortest
// emitted witness, then enforces diversity before presentation's Top-10 limit.
// Scores describe navigation priority and must never become confidence/verdicts.
func RankPrescanCandidates(input []PrescanCandidate) []PrescanCandidate {
	best := map[string]PrescanCandidate{}
	for _, c := range input {
		key := candidateKey(c)
		old, ok := best[key]
		if !ok || c.Hops < old.Hops || (c.Hops == old.Hops && c.Score > old.Score) || (c.Hops == old.Hops && c.Score == old.Score && c.PathIndex < old.PathIndex) {
			best[key] = c
		}
	}
	groups := map[string][]PrescanCandidate{}
	for _, c := range best {
		group := prescanSourceKey(c) + "\x00" + c.Sink.Path
		groups[group] = append(groups[group], c)
	}
	out := make([]PrescanCandidate, 0, len(best))
	for _, group := range groups {
		// Diversity is decided by shortest emitted witnesses within each
		// source/file pair, before global navigation scores are applied.
		sort.Slice(group, func(i, j int) bool {
			a, b := group[i], group[j]
			if a.Hops != b.Hops {
				return a.Hops < b.Hops
			}
			if a.Score != b.Score {
				return a.Score > b.Score
			}
			if candidateKey(a) != candidateKey(b) {
				return candidateKey(a) < candidateKey(b)
			}
			return a.PathIndex < b.PathIndex
		})
		out = append(out, group[:min(2, len(group))]...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Hops != b.Hops {
			return a.Hops < b.Hops
		}
		if candidateKey(a) != candidateKey(b) {
			return candidateKey(a) < candidateKey(b)
		}
		return a.PathIndex < b.PathIndex
	})
	return out
}

const PrescanSummaryHeader = "PRE-SCANNED TAINT CANDIDATES (deterministic CodeQL clues, not verdicts)"

// RenderPrescanSummary is a bounded view. Full witnesses remain in ToolFact;
// neither ranking nor hop excerpts truncate the underlying evidence artifact.
func RenderPrescanSummary(fact artifacts.ToolFact, ref string) string {
	var meta PrescanResult
	_ = json.Unmarshal(fact.Result, &meta)
	note := "These are structural may-flow clues, not verdicts or proof of runtime reachability. Counts cover emitted witnesses, not all program paths. Read source and sink code before opening a lead."
	if fact.Status != "success" {
		note = "Prescan did not complete usable analysis; failure does NOT prove safety. " + note
	} else if meta.TotalPaths == 0 {
		note = ZeroPathNotice + " " + note
	}
	base := fmt.Sprintf("%s\nfact_ref=%s | status=%s | emitted_unique_paths=%d | ranked_candidates=%d\n%s\n\n", PrescanSummaryHeader, ref, compactText(fact.Status, 32), meta.TotalPaths, len(meta.Candidates), note)
	if fact.Error != "" {
		base += "coverage_gap=" + compactText(fact.Error, 500) + "\n"
	}
	if len(base) > PrescanSummaryMaxBytes-128 {
		// OS paths are normally bounded well below this, but never silently
		// truncate a fact reference into a different, unresolvable identifier.
		return PrescanSummaryHeader + "\nSummary metadata exceeds 12 KiB; no partial fact reference was exposed. Inspect the persisted prescan artifact; this is not proof of safety."
	}
	var blocks strings.Builder
	shown := 0
	for rank, c := range meta.Candidates[:min(10, len(meta.Candidates))] {
		if c.PathIndex < 0 || c.PathIndex >= len(fact.Paths) {
			continue
		}
		block := renderPrescanCandidate(rank+1, c, fact.Paths[c.PathIndex], ref)
		if len(base)+blocks.Len()+len(block)+1+160 > PrescanSummaryMaxBytes {
			break
		}
		blocks.WriteString(block)
		blocks.WriteByte('\n') // Whole-candidate paragraphs survive Planner re-bounding.
		shown++
	}
	footer := fmt.Sprintf("shown=%d; remaining_ranked_candidates=%d; hop excerpts may omit nodes; inspect fact_ref for complete emitted witnesses.\n", shown, max(0, len(meta.Candidates)-shown))
	return base + blocks.String() + footer
}

func renderPrescanCandidate(rank int, c PrescanCandidate, path []artifacts.ToolPathStep, ref string) string {
	// Identifiers are read_file targets, not display excerpts. Quote control
	// characters without shortening names into nonexistent paths or symbols.
	// The outer renderer omits a whole candidate if its real header cannot fit.
	header := fmt.Sprintf("#%d | fact_ref=%s | %s (%s:%d) -> [%d nodes] -> %s (%s:%d) | signal=%s\n", rank, ref, strconv.Quote(c.SourceFunc), strconv.Quote(c.Source.Path), c.Source.StartLine, c.Hops, strconv.Quote(c.SinkFunc), strconv.Quote(c.Sink.Path), c.Sink.StartLine, c.SourceSignal)
	var b strings.Builder
	b.WriteString(header)
	// Preserve explicit node indices; excerpts never invent a shortcut edge.
	indices := make([]int, 0, min(10, len(path)))
	for i := 0; i < len(path) && i < 10; i++ {
		indices = append(indices, i)
	}
	if len(path) > 10 {
		indices[len(indices)-1] = len(path) - 1
	}
	shown := 0
	for _, i := range indices {
		step := path[i]
		line := fmt.Sprintf("  [%d] %s:%d %s :: %s\n", i, compactText(step.Location.Path, 90), step.Location.StartLine, compactText(step.Location.Symbol, 45), compactText(step.Message, 70))
		if b.Len()+len(line) > max(1100, len(header)) {
			break
		}
		b.WriteString(line)
		shown++
	}
	if shown < len(path) {
		fmt.Fprintf(&b, "  ... %d unrendered nodes; full path_index=%d in fact_ref\n", len(path)-shown, c.PathIndex)
	}
	return b.String()
}
