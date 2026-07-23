package trustirfacts

import "sync"

// llmFactTables is the LLM-annotation pipeline's output registry, checked
// by factTableFor (facttable.go) BEFORE the deterministic knownFactTables
// fixture. This is how the annotation pipeline (annotate.go, resolver.go)
// hands its result to the unchanged Run entry point without adding a field
// to Request or a parameter to Run — the parallel PR-06 agent's
// Run/RunAndPersist/Request signatures stay exactly as specified (see this
// package's doc.go).
//
// Both sources coexist by construction, per the task's explicit "keep the
// deterministic path" requirement:
//
//	table, report, err := trustirfacts.AnnotateFactTable(ctx, client, registry, sourceRoot)
//	if err == nil && !table.Empty() {
//	    trustirfacts.SetFactTable(repository, table) // LLM path now wins for repository
//	}
//	fact, err := trustirfacts.Run(ctx, eng, req)
//
// A caller that never calls AnnotateFactTable — no LLM configured,
// offline/CI, or the pipeline produced no resolved facts and the caller
// chose not to register an empty table — leaves llmFactTables with no entry
// for that repository, and factTableFor falls through to knownFactTables
// exactly as the deterministic skeleton did before this file existed.
var (
	llmFactTablesMu sync.RWMutex
	llmFactTables   = map[string]FactTable{}
)

// SetFactTable registers table as the fact table Run should use for
// repository, taking priority over any knownFactTables entry for the same
// repository. Safe for concurrent use.
func SetFactTable(repository string, table FactTable) {
	llmFactTablesMu.Lock()
	defer llmFactTablesMu.Unlock()
	llmFactTables[normalizeRepo(repository)] = table
}

// ResetFactTables clears every LLM-registered fact table. Tests use this to
// keep the package-level registry from leaking state across test cases.
func ResetFactTables() {
	llmFactTablesMu.Lock()
	defer llmFactTablesMu.Unlock()
	llmFactTables = map[string]FactTable{}
}

func lookupLLMFactTable(key string) (FactTable, bool) {
	llmFactTablesMu.RLock()
	defer llmFactTablesMu.RUnlock()
	t, ok := llmFactTables[key]
	return t, ok
}
