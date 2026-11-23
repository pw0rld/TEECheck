// Package topology computes neutral, deterministic 3-hop entry call closures,
// cross-function struct-field access bridges, and 4-bucket surface partitions
// from RepoFacts. It contains zero vulnerability heuristics or keyword rules:
// all relationships derive strictly from AST definitions, resolved call edges,
// and recorded struct-field accesses.
package topology

import (
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

const (
	MaxClosureDepth      = 3
	MaxMembersPerClosure = 24
	MaxPerFileStreak     = 2
)

var orderedBuckets = []struct {
	name        string
	description string
}{
	{
		name:        artifacts.SurfaceBucketDispatchTables,
		description: "Entry closures rooted at global function-pointer dispatch tables (syscalls, command tables, IPC handlers) up to 3 resolved call hops.",
	},
	{
		name:        artifacts.SurfaceBucketRootBoundaries,
		description: "Entry closures rooted at uncalled external-linkage definitions and boundary entry points up to 3 resolved call hops.",
	},
	{
		name:        artifacts.SurfaceBucketStructBridges,
		description: "Entry closures whose 0..3 hop members directly assign struct fields also accessed by other functions or modules.",
	},
	{
		name:        artifacts.SurfaceBucketSharedStateLifecycle,
		description: "Entry closures in modules where closures both directly assign and non-write-access the same struct fields across entry paths.",
	},
}

// Build constructs the deterministic BoundaryTopology view from RepoFacts and
// validated EntrySurfaces.
func Build(runID string, scope artifacts.ScannedScope, facts artifacts.RepoFacts, entries []artifacts.EntrySurface) artifacts.BoundaryTopology {
	out := artifacts.BoundaryTopology{
		SchemaVersion:   artifacts.SchemaVersionBoundaryTopologyV1,
		RunID:           runID,
		Scope:           scope,
		MaxClosureDepth: MaxClosureDepth,
	}
	if len(facts.Symbols) == 0 || len(entries) == 0 {
		return out
	}

	capsuleByID := make(map[artifacts.SymbolID]artifacts.FunctionCapsule, len(facts.Capsules))
	for _, c := range facts.Capsules {
		capsuleByID[c.SymbolID] = c
	}
	symbolByID := make(map[artifacts.SymbolID]artifacts.Symbol, len(facts.Symbols))
	for _, s := range facts.Symbols {
		symbolByID[s.SymbolID] = s
	}

	callees := make(map[artifacts.SymbolID][]artifacts.SymbolID, len(facts.Capsules))
	for _, edge := range facts.CallEdges {
		if edge.CallerID == "" || edge.CalleeID == "" || edge.CallerID == edge.CalleeID {
			continue
		}
		callees[edge.CallerID] = append(callees[edge.CallerID], edge.CalleeID)
	}
	for caller := range callees {
		callees[caller] = uniqueSortedSymbolIDs(callees[caller])
	}

	bridges := BuildStructFieldBridges(facts.Capsules)
	out.StructFieldBridges = bridges

	bridgedFields := map[string]bool{}
	for _, br := range bridges {
		if br.CrossModule || len(br.NonWriteAccessors) > 0 {
			bridgedFields[br.Field] = true
		}
	}

	sortedEntries := append([]artifacts.EntrySurface(nil), entries...)
	sort.Slice(sortedEntries, func(i, j int) bool {
		if sortedEntries[i].Module != sortedEntries[j].Module {
			return sortedEntries[i].Module < sortedEntries[j].Module
		}
		if sortedEntries[i].Path != sortedEntries[j].Path {
			return sortedEntries[i].Path < sortedEntries[j].Path
		}
		if sortedEntries[i].StartLine != sortedEntries[j].StartLine {
			return sortedEntries[i].StartLine < sortedEntries[j].StartLine
		}
		return sortedEntries[i].SymbolID < sortedEntries[j].SymbolID
	})

	closures := make([]artifacts.EntryClosure, 0, len(sortedEntries))
	type modField struct{ mod, field string }
	fieldTouchCount := map[modField]int{}
	fieldWriteCount := map[modField]int{}
	fieldNonWriteCount := map[modField]int{}

	for _, entry := range sortedEntries {
		closure := buildSingleClosure(entry, callees, capsuleByID, symbolByID)
		for _, f := range closure.FieldAccesses {
			fieldTouchCount[modField{closure.RootModule, f}]++
		}
		for _, f := range closure.DirectFieldWrites {
			fieldWriteCount[modField{closure.RootModule, f}]++
		}
		for _, f := range closure.NonWriteFieldAccesses {
			fieldNonWriteCount[modField{closure.RootModule, f}]++
		}
		closures = append(closures, closure)
	}

	bucketMap := map[string][]artifacts.EntryClosure{}
	for i := range closures {
		c := &closures[i]
		rootCap := capsuleByID[c.RootSymbolID]
		var buckets []string

		if hasSignal(c.Signals, artifacts.EntrySignalGlobalFunctionPointerInitializer) {
			buckets = append(buckets, artifacts.SurfaceBucketDispatchTables)
		}
		if hasSignal(c.Signals, artifacts.EntrySignalNoResolvedInternalCallers) ||
			(hasSignal(c.Signals, artifacts.EntrySignalExternalLinkage) && len(rootCap.CalledBy) == 0 && !hasSignal(c.Signals, artifacts.EntrySignalGlobalFunctionPointerInitializer)) {
			buckets = append(buckets, artifacts.SurfaceBucketRootBoundaries)
		}
		hasBridge := false
		for _, f := range c.DirectFieldWrites {
			if bridgedFields[f] {
				hasBridge = true
				break
			}
		}
		if hasBridge {
			buckets = append(buckets, artifacts.SurfaceBucketStructBridges)
		}
		hasSharedState := false
		for _, f := range c.FieldAccesses {
			mf := modField{c.RootModule, f}
			if fieldWriteCount[mf] >= 1 && fieldNonWriteCount[mf] >= 1 && fieldTouchCount[mf] >= 2 {
				hasSharedState = true
				break
			}
		}
		if hasSharedState {
			buckets = append(buckets, artifacts.SurfaceBucketSharedStateLifecycle)
		}

		c.Buckets = buckets
		for _, b := range buckets {
			bucketMap[b] = append(bucketMap[b], *c)
		}
	}

	out.EntryClosures = closures

	partitions := make([]artifacts.SurfacePartition, 0, len(orderedBuckets))
	for _, spec := range orderedBuckets {
		diversified := DiversifyClosures(bucketMap[spec.name], MaxPerFileStreak)
		mods := map[string]bool{}
		ids := make([]artifacts.SymbolID, 0, len(diversified))
		for _, c := range diversified {
			if c.RootModule != "" {
				mods[c.RootModule] = true
			}
			ids = append(ids, c.RootSymbolID)
		}
		partitions = append(partitions, artifacts.SurfacePartition{
			Bucket:        spec.name,
			Description:   spec.description,
			ClosureCount:  len(ids),
			ModuleCount:   len(mods),
			RootSymbolIDs: ids,
		})
	}
	out.SurfacePartitions = partitions
	return out
}

// BuildStructFieldBridges connects functions that directly assign "Type.field"
// with functions that access the same "Type.field". Two functions that only
// directly assign the field (with no non-write accessor and within the same
// module) are NOT paired unless another function accesses the field without
// direct assignment or across modules.
func BuildStructFieldBridges(capsules []artifacts.FunctionCapsule) []artifacts.StructFieldBridge {
	directWriters := map[string][]artifacts.SymbolID{}
	nonWriteAccessors := map[string][]artifacts.SymbolID{}
	accessors := map[string][]artifacts.SymbolID{}
	modBySym := make(map[artifacts.SymbolID]string, len(capsules))

	for _, c := range capsules {
		modBySym[c.SymbolID] = c.Module
		writeSet := map[string]bool{}
		touchSet := map[string]bool{}
		for _, f := range c.DirectFieldWrites {
			if f == "" {
				continue
			}
			writeSet[f] = true
			touchSet[f] = true
			directWriters[f] = append(directWriters[f], c.SymbolID)
		}
		for _, f := range c.FieldAccesses {
			if f == "" {
				continue
			}
			touchSet[f] = true
			if !writeSet[f] {
				nonWriteAccessors[f] = append(nonWriteAccessors[f], c.SymbolID)
			}
		}
		for f := range touchSet {
			accessors[f] = append(accessors[f], c.SymbolID)
		}
	}

	fields := make([]string, 0, len(directWriters))
	for f := range directWriters {
		if len(accessors[f]) == 0 {
			continue
		}
		fields = append(fields, f)
	}
	sort.Strings(fields)

	out := make([]artifacts.StructFieldBridge, 0, len(fields))
	for _, f := range fields {
		ws := uniqueSortedSymbolIDs(directWriters[f])
		nwa := uniqueSortedSymbolIDs(nonWriteAccessors[f])
		acc := uniqueSortedSymbolIDs(accessors[f])
		if len(acc) < 2 {
			continue
		}
		mods := map[string]bool{}
		for _, id := range acc {
			if m := modBySym[id]; m != "" {
				mods[m] = true
			}
		}
		crossMod := len(mods) >= 2
		if len(nwa) == 0 && !crossMod {
			continue
		}
		out = append(out, artifacts.StructFieldBridge{
			Field:             f,
			DirectWriters:     ws,
			NonWriteAccessors: nwa,
			Accessors:         acc,
			CrossModule:       crossMod,
		})
	}
	return out
}

func nonWriteSubset(accesses, directWrites []string) []string {
	if len(accesses) == 0 {
		return nil
	}
	w := make(map[string]bool, len(directWrites))
	for _, f := range directWrites {
		w[f] = true
	}
	var out []string
	for _, f := range accesses {
		if f != "" && !w[f] {
			out = append(out, f)
		}
	}
	return uniqueSortedStrings(out)
}

func buildSingleClosure(
	entry artifacts.EntrySurface,
	callees map[artifacts.SymbolID][]artifacts.SymbolID,
	capsuleByID map[artifacts.SymbolID]artifacts.FunctionCapsule,
	symbolByID map[artifacts.SymbolID]artifacts.Symbol,
) artifacts.EntryClosure {
	type queueItem struct {
		id  artifacts.SymbolID
		hop int
	}
	visited := map[artifacts.SymbolID]bool{entry.SymbolID: true}
	queue := []queueItem{{id: entry.SymbolID, hop: 0}}

	var members []artifacts.ClosureMember
	var allWrites, allNonWrites, allAccesses []string
	maxHopSeen := 0
	truncated := false

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.hop > maxHopSeen {
			maxHopSeen = cur.hop
		}

		capRec, hasCap := capsuleByID[cur.id]
		symRec, hasSym := symbolByID[cur.id]
		member := artifacts.ClosureMember{
			SymbolID: cur.id,
			Hop:      cur.hop,
		}
		switch {
		case hasCap:
			member.Name = capRec.Name
			member.Path = capRec.File
			member.Module = capRec.Module
			member.Line = capRec.Line
			member.DirectFieldWrites = uniqueSortedStrings(capRec.DirectFieldWrites)
			member.FieldAccesses = uniqueSortedStrings(capRec.FieldAccesses)
			member.NonWriteFieldAccesses = nonWriteSubset(member.FieldAccesses, member.DirectFieldWrites)
		case hasSym:
			member.Name = symRec.Name
			member.Path = symRec.File
			member.Module = symRec.Module
			member.Line = symRec.StartLine
		default:
			member.Name = entry.Name
			member.Path = entry.Path
			member.Module = entry.Module
			member.Line = entry.StartLine
		}

		allWrites = append(allWrites, member.DirectFieldWrites...)
		allNonWrites = append(allNonWrites, member.NonWriteFieldAccesses...)
		allAccesses = append(allAccesses, member.FieldAccesses...)

		if len(members) < MaxMembersPerClosure {
			members = append(members, member)
		} else {
			truncated = true
		}

		if cur.hop >= MaxClosureDepth {
			continue
		}
		for _, next := range callees[cur.id] {
			if visited[next] {
				continue
			}
			visited[next] = true
			queue = append(queue, queueItem{id: next, hop: cur.hop + 1})
		}
	}

	return artifacts.EntryClosure{
		RootSymbolID:          entry.SymbolID,
		RootName:              entry.Name,
		RootPath:              entry.Path,
		RootModule:            entry.Module,
		RootStartLine:         entry.StartLine,
		RootEndLine:           entry.EndLine,
		Signals:               sortedStrings(entry.Signals),
		MaxDepth:              maxHopSeen,
		MembersTruncated:      truncated,
		Members:               members,
		DirectFieldWrites:     uniqueSortedStrings(allWrites),
		NonWriteFieldAccesses: uniqueSortedStrings(allNonWrites),
		FieldAccesses:         uniqueSortedStrings(allAccesses),
	}
}

// DiversifyClosures performs a strict two-level round-robin (Module -> File):
// each wave visits every active module once, picks the next file queue in that
// module via a persistent per-module cursor, and emits at most maxPerFile items
// from that file before advancing to another module/file.
func DiversifyClosures(in []artifacts.EntryClosure, maxPerFile int) []artifacts.EntryClosure {
	if len(in) <= 1 {
		return append([]artifacts.EntryClosure(nil), in...)
	}
	if maxPerFile <= 0 {
		maxPerFile = MaxPerFileStreak
	}

	sorted := append([]artifacts.EntryClosure(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		vi, vj := isUtilityModulePath(sorted[i].RootModule), isUtilityModulePath(sorted[j].RootModule)
		if vi != vj {
			return !vi
		}
		si, sj := structuralRichness(sorted[i]), structuralRichness(sorted[j])
		if si != sj {
			return si > sj
		}
		if sorted[i].RootModule != sorted[j].RootModule {
			return sorted[i].RootModule < sorted[j].RootModule
		}
		if sorted[i].RootPath != sorted[j].RootPath {
			return sorted[i].RootPath < sorted[j].RootPath
		}
		if sorted[i].RootStartLine != sorted[j].RootStartLine {
			return sorted[i].RootStartLine < sorted[j].RootStartLine
		}
		return sorted[i].RootSymbolID < sorted[j].RootSymbolID
	})

	type fileQueue struct {
		path  string
		items []artifacts.EntryClosure
	}
	type moduleRing struct {
		module string
		files  []*fileQueue
		cursor int
	}

	var modules []*moduleRing
	modByName := map[string]*moduleRing{}
	fileByPath := map[string]*fileQueue{}

	for _, c := range sorted {
		m, ok := modByName[c.RootModule]
		if !ok {
			m = &moduleRing{module: c.RootModule}
			modByName[c.RootModule] = m
			modules = append(modules, m)
		}
		fq, ok := fileByPath[c.RootPath]
		if !ok {
			fq = &fileQueue{path: c.RootPath}
			fileByPath[c.RootPath] = fq
			m.files = append(m.files, fq)
		}
		fq.items = append(fq.items, c)
	}

	out := make([]artifacts.EntryClosure, 0, len(sorted))
	remaining := len(sorted)
	for remaining > 0 {
		for _, m := range modules {
			if len(m.files) == 0 {
				continue
			}
			var chosen *fileQueue
			nFiles := len(m.files)
			for step := 0; step < nFiles; step++ {
				idx := (m.cursor + step) % nFiles
				if len(m.files[idx].items) > 0 {
					chosen = m.files[idx]
					m.cursor = (idx + 1) % nFiles
					break
				}
			}
			if chosen == nil {
				continue
			}
			take := maxPerFile
			if take > len(chosen.items) {
				take = len(chosen.items)
			}
			out = append(out, chosen.items[:take]...)
			chosen.items = chosen.items[take:]
			remaining -= take
		}
	}
	return out
}

func structuralRichness(c artifacts.EntryClosure) int {
	score := 0
	if len(c.Members) > 1 {
		score += 2
	}
	if len(c.DirectFieldWrites) > 0 {
		score += 2
	}
	if hasSignal(c.Signals, artifacts.EntrySignalBufferLengthParameters) {
		score += 1
	}
	return score
}

func isUtilityModulePath(mod string) bool {
	first, _, _ := strings.Cut(strings.TrimPrefix(mod, "/"), "/")
	return first == "lib" || first == "third_party" || first == "vendor" || first == "external"
}

func hasSignal(signals []string, want string) bool {
	for _, s := range signals {
		if s == want {
			return true
		}
	}
	return false
}

func sortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func uniqueSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]bool, len(in))
	for _, s := range in {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedSymbolIDs(in []artifacts.SymbolID) []artifacts.SymbolID {
	if len(in) == 0 {
		return nil
	}
	set := make(map[artifacts.SymbolID]bool, len(in))
	for _, s := range in {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]artifacts.SymbolID, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
