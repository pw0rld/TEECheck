package pipeline

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// recordingEngine satisfies trustirfacts.Engine and remembers what it was
// asked to analyze, so a test can assert on invocation rather than on the
// contents of a database it never builds.
type recordingEngine struct {
	available bool
	analyzed  []string // query files passed to Analyze
	results   []codeql.Result
}

func (e *recordingEngine) Available() bool { return e.available }

func (e *recordingEngine) CreateDatabase(context.Context, codeql.CreateDBOptions) error { return nil }

func (e *recordingEngine) Analyze(_ context.Context, opts codeql.AnalyzeOptions) ([]codeql.Result, error) {
	e.analyzed = append(e.analyzed, opts.Queries...)
	return e.results, nil
}

func invariantWithTWEs(id string, twes ...string) artifacts.ProjectInvariant {
	return artifacts.ProjectInvariant{InvariantID: id, RelatedTWEs: twes}
}

// The deterministic evidence a run's own invariants call for must be
// collected, not left to the model's choice. Across four runs on
// CVE-2026-44362 the planner reached for the fact layer once, while the query
// answers both revisions correctly on its own.
func TestPlanTWEOperations_FiresOnInvariantRelatedTWE(t *testing.T) {
	ops := planTWEOperations([]artifacts.ProjectInvariant{
		invariantWithTWEs("INV-STATE-001", "TWE-STATE-001"),
	})
	if len(ops) != 1 {
		t.Fatalf("ops = %v, want one operation for TWE-STATE-001", ops)
	}
	if ops[0] != trustirfacts.OperationRollbackVersionPropagation {
		t.Fatalf("ops[0] = %q", ops[0])
	}
}

// A family with no executable query must produce no call at all — not an
// unsupported ToolFact, which would put a persisted artifact on disk for a
// query that was never going to run.
func TestPlanTWEOperations_SkipsFamiliesWithoutAQuery(t *testing.T) {
	ops := planTWEOperations([]artifacts.ProjectInvariant{
		invariantWithTWEs("INV-FLOW-001", "TWE-FLOW-001", "TWE-GUARD-001"),
	})
	if len(ops) != 0 {
		t.Fatalf("ops = %v, want none — neither family has a query", ops)
	}
}

// Two invariants naming the same TWE must not run the query twice. The fact
// is content-addressed by repository+commit+operation, so a second run would
// recompile and re-execute for a byte-identical answer.
func TestPlanTWEOperations_Deduplicates(t *testing.T) {
	ops := planTWEOperations([]artifacts.ProjectInvariant{
		invariantWithTWEs("INV-STATE-001", "TWE-STATE-001"),
		invariantWithTWEs("INV-STATE-002", "TWE-STATE-001"),
	})
	if len(ops) != 1 {
		t.Fatalf("ops = %v, want one after dedup", ops)
	}
}

// No invariants, or invariants with no related TWEs, means nothing to collect.
func TestPlanTWEOperations_EmptyInput(t *testing.T) {
	if ops := planTWEOperations(nil); len(ops) != 0 {
		t.Fatalf("ops = %v, want none", ops)
	}
	if ops := planTWEOperations([]artifacts.ProjectInvariant{invariantWithTWEs("INV-1")}); len(ops) != 0 {
		t.Fatalf("ops = %v, want none", ops)
	}
}

// stubRunner records the requests it was handed and returns a canned fact.
func stubRunner(status string, locations int, reqs *[]trustirfacts.Request) factRunner {
	return func(_ context.Context, _ trustirfacts.Engine, req trustirfacts.Request) (artifacts.ToolFact, string, error) {
		*reqs = append(*reqs, req)
		fact := artifacts.ToolFact{Status: status}
		for i := 0; i < locations; i++ {
			fact.Locations = append(fact.Locations, artifacts.ToolLocation{Path: "f.c", StartLine: i + 1})
		}
		return fact, "/runs/x/02_tool_facts/trustir/fact.json", nil
	}
}

// A successful fact is collected, and the request carries the pinned
// repository and commit the run is about.
func TestPrefetchFactLayer_CollectsSuccessfulFacts(t *testing.T) {
	var reqs []trustirfacts.Request
	refs := prefetchFactLayer(context.Background(), &recordingEngine{available: true},
		"codeql/trustir/cpp", "/runs/x",
		"https://github.com/OP-TEE/optee_os", "a9386bf",
		[]artifacts.ProjectInvariant{invariantWithTWEs("INV-STATE-001", "TWE-STATE-001")},
		nil, stubRunner(trustirfacts.StatusSuccess, 1, &reqs))

	if len(reqs) != 1 {
		t.Fatalf("fact-layer calls = %d, want 1", len(reqs))
	}
	if reqs[0].Operation != trustirfacts.OperationRollbackVersionPropagation {
		t.Errorf("operation = %q", reqs[0].Operation)
	}
	if reqs[0].Repository != "https://github.com/OP-TEE/optee_os" || reqs[0].Commit != "a9386bf" {
		t.Errorf("request must pin repository+commit: %+v", reqs[0])
	}
	if len(refs) != 1 {
		t.Fatalf("refs = %v, want one persisted ToolFact path", refs)
	}
}

// Zero locations on a success is still collected: "we looked and found
// nothing" is evidence, and it is exactly what the fixed half of a
// differential is supposed to produce.
func TestPrefetchFactLayer_ZeroLocationsIsStillEvidence(t *testing.T) {
	var reqs []trustirfacts.Request
	refs := prefetchFactLayer(context.Background(), &recordingEngine{available: true},
		"codeql/trustir/cpp", "/runs/x", "https://github.com/OP-TEE/optee_os", "43ed01d",
		[]artifacts.ProjectInvariant{invariantWithTWEs("INV-STATE-001", "TWE-STATE-001")},
		nil, stubRunner(trustirfacts.StatusSuccess, 0, &reqs))
	if len(refs) != 1 {
		t.Fatalf("refs = %v, want the zero-location fact collected", refs)
	}
}

// unsupported / unresolved / error are real answers about the tool's reach,
// not evidence about the code. Handing one downstream as a tool_fact_ref
// would dress "we could not look" up as "we looked".
func TestPrefetchFactLayer_NonSuccessIsNotCollected(t *testing.T) {
	for _, status := range []string{trustirfacts.StatusUnsupported, trustirfacts.StatusUnresolved, trustirfacts.StatusError} {
		var reqs []trustirfacts.Request
		refs := prefetchFactLayer(context.Background(), &recordingEngine{available: true},
			"codeql/trustir/cpp", "/runs/x", "https://github.com/OP-TEE/optee_os", "deadbeef",
			[]artifacts.ProjectInvariant{invariantWithTWEs("INV-STATE-001", "TWE-STATE-001")},
			nil, stubRunner(status, 0, &reqs))
		if len(refs) != 0 {
			t.Errorf("status %q must not be collected, got %v", status, refs)
		}
	}
}

// Nothing to collect means the fact layer is never called at all.
func TestPrefetchFactLayer_NoOperationsMeansNoCalls(t *testing.T) {
	var reqs []trustirfacts.Request
	prefetchFactLayer(context.Background(), &recordingEngine{available: true},
		"codeql/trustir/cpp", "/runs/x", "https://github.com/OP-TEE/optee_os", "deadbeef",
		[]artifacts.ProjectInvariant{invariantWithTWEs("INV-FLOW-001", "TWE-FLOW-001")},
		nil, stubRunner(trustirfacts.StatusSuccess, 1, &reqs))
	if len(reqs) != 0 {
		t.Errorf("no family has a query — the fact layer must not be called: %+v", reqs)
	}
}
