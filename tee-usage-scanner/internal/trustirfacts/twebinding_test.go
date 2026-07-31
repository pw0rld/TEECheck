package trustirfacts

import (
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

func loadCatalogIDs(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "catalog.yml")
	defs, err := twe.LoadDefinitions(path)
	if err != nil {
		t.Skipf("catalog not readable at %s: %v", path, err)
	}
	ids := make(map[string]bool, len(defs))
	for _, d := range defs {
		ids[d.ID] = true
	}
	return ids
}

// The knowledge layer has to be able to reach the fact layer. Before this
// binding existed the connection was prose: OperationRollbackVersionPropagation's
// doc comment said "TWE-STATE-001" and nothing could read it, while the
// catalog's own query_modules field named .ql files that exist only in the
// sibling tee-audit tree. Two naming systems, no bridge — and across four runs
// on CVE-2026-44362 the planner reached for the fact layer once.
func TestOperationForTWE_StateRollback(t *testing.T) {
	op, ok := OperationForTWE("TWE-STATE-001")
	if !ok {
		t.Fatal("TWE-STATE-001 must map to an operation — it is the one family with an executable query")
	}
	if op != OperationRollbackVersionPropagation {
		t.Fatalf("op = %q, want %q", op, OperationRollbackVersionPropagation)
	}
}

// A family with no query must say so, rather than name a file that is not
// there. This is what query_modules got wrong for all 19 entries.
func TestOperationForTWE_FamiliesWithoutAQueryReportFalse(t *testing.T) {
	for _, id := range []string{"TWE-FLOW-001", "TWE-GUARD-001", "TWE-BIND-001", "TWE-CONFIG-001"} {
		if op, ok := OperationForTWE(id); ok {
			t.Errorf("%s claims operation %q, but its family has no executable query", id, op)
		}
	}
}

// Every operation the binding names must actually be runnable. A binding
// entry is a promise that Run will not report unsupported.
func TestTWEBinding_NamesOnlyExecutableOperations(t *testing.T) {
	for tweID, op := range tweOperations {
		if _, ok := operationQueries[op]; !ok {
			t.Errorf("%s binds %q, which has no query file in operationQueries", tweID, op)
		}
	}
}

// Every TWE id in the binding must exist in the real catalog. A typo here
// silently disables the binding for that family, which is exactly how
// query_modules stayed wrong for nineteen entries without anyone noticing.
func TestTWEBinding_NamesOnlyRealTWEs(t *testing.T) {
	ids := loadCatalogIDs(t)
	for tweID := range tweOperations {
		if !ids[tweID] {
			t.Errorf("binding names %q, which is not in the catalog", tweID)
		}
	}
}

// And the other direction: an executable query no TWE points at is
// unreachable from the knowledge layer. The planner is steered by TWEs, so a
// query nothing binds to can only be invoked by a model guessing its name.
func TestTWEBinding_EveryExecutableOperationIsReachable(t *testing.T) {
	bound := make(map[Operation]bool, len(tweOperations))
	for _, op := range tweOperations {
		bound[op] = true
	}
	for op := range operationQueries {
		if !bound[op] {
			t.Errorf("operation %q is executable but no TWE binds to it — nothing in the "+
				"knowledge layer can cause it to run", op)
		}
	}
}
