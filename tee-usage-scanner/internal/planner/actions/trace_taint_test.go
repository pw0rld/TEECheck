package actions

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/taint"
)

func TestTraceTaintConcurrentCacheRequestsSpendOnce(t *testing.T) {
	h, req, engine, _, taken := traceActionFixture(t)
	var wg sync.WaitGroup
	results := make(chan ActionResult, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- h.Run(context.Background(), req) }()
	}
	wg.Wait()
	close(results)
	for result := range results {
		if !result.OK {
			t.Fatal(result.Error)
		}
	}
	if *taken != 1 || engine.calls != 1 {
		t.Fatalf("duplicate cache requests spent %d attempts and %d engine calls", *taken, engine.calls)
	}
}

type traceActionEngine struct {
	calls   int
	results []codeql.Result
	query   string
}

func (*traceActionEngine) Available() bool { return true }
func (e *traceActionEngine) Analyze(_ context.Context, opts codeql.AnalyzeOptions) ([]codeql.Result, error) {
	e.calls++
	if len(opts.Queries) == 1 {
		data, err := os.ReadFile(opts.Queries[0])
		if err != nil {
			return nil, err
		}
		e.query = string(data)
	}
	return e.results, nil
}

type traceActionDB struct{ calls int }

func (d *traceActionDB) Ensure(context.Context, codedb.Scope) (string, error) {
	d.calls++
	return "shared-db", nil
}
func (*traceActionDB) Path(codedb.Scope) string  { return "shared-db" }
func (*traceActionDB) State(codedb.Scope) string { return codedb.StateReady }

func traceActionFixture(t *testing.T) (*TraceTaintHandler, ActionRequest, *traceActionEngine, *traceActionDB, *int) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.c"), []byte("int entry(int value) { return value; }\nint consume(int value) { return value; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "revision", root)
	m := artifacts.Manifest{RunID: "trace-action", RepoURL: "fixture", Commit: "revision", LocalPath: root, Scope: scope}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), m); err != nil {
		t.Fatal(err)
	}
	facts := artifacts.RepoFacts{SchemaVersion: artifacts.SchemaVersionRepoFactsV1, RunID: m.RunID, Scope: scope, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable}, Symbols: []artifacts.Symbol{
		{SymbolID: "cpp:entry.c:1:entry(int)", Name: "entry", File: "entry.c", StartLine: 1, Signature: "(int)"},
		{SymbolID: "cpp:entry.c:2:consume(int)", Name: "consume", File: "entry.c", StartLine: 2, Signature: "(int)"},
	}}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(run), facts); err != nil {
		t.Fatal(err)
	}
	engine := &traceActionEngine{results: []codeql.Result{{Paths: [][]codeql.PathStep{{{Path: "entry.c", StartLine: 1, Function: "entry", Expression: "value"}, {Path: "entry.c", StartLine: 2, Function: "consume", Expression: "consume(value)"}}}}}}
	db := &traceActionDB{}
	taken := 0
	request := ActionRequest{Name: TraceTaintAction, RunDir: run, RepoRoot: root, Repository: m.RepoURL, Commit: m.Commit, Args: json.RawMessage(`{"source_func":"entry","sink_func":"consume"}`), TracePolicy: &TracePolicy{Investigation: true, HasLead: true, ObservedSymbol: func(id artifacts.SymbolID) bool { return id == facts.Symbols[0].SymbolID }, TakeQuery: func() bool { taken++; return true }}}
	return &TraceTaintHandler{Service: taint.NewService(engine, db)}, request, engine, db, &taken
}

func TestTraceTaintRejectsUntrustedArgumentsBeforeExecution(t *testing.T) {
	for _, args := range []string{
		`{"source_func":"entry\" or 1=1","sink_func":"consume"}`,
		`{"source_func":"entry","sink_func":"consume); select x"}`,
		`{"source_func":"entry","sink_kind":"array_index","barrier_funcs":["x/*"]}`,
		`{"source_func":"entry","sink_func":"consume","ql":"import cpp"}`,
		`{"source_func":"missing","sink_func":"consume"}`,
		`{"source_func":"entry","sink_kind":"raw_ql"}`,
		`{"source_func":"entry","sink_func":"consume"} {"query":"second object"}`,
	} {
		t.Run(args, func(t *testing.T) {
			h, req, engine, db, taken := traceActionFixture(t)
			req.Args = json.RawMessage(args)
			res := h.Run(context.Background(), req)
			if res.OK || res.Error == "" || engine.calls != 0 || db.calls != 0 || *taken != 0 {
				t.Fatalf("untrusted request reached execution: %+v engine=%d db=%d quota=%d", res, engine.calls, db.calls, *taken)
			}
		})
	}
}

func TestTraceTaintRequiresCurrentInvestigationAndObservedDefinition(t *testing.T) {
	for _, mode := range []string{"no policy", "reconnaissance", "no lead", "unobserved", "no observation callback", "no quota callback"} {
		t.Run(mode, func(t *testing.T) {
			h, req, engine, db, taken := traceActionFixture(t)
			switch mode {
			case "no policy":
				req.TracePolicy = nil
			case "reconnaissance":
				req.TracePolicy.Investigation = false
			case "no lead":
				req.TracePolicy.HasLead = false
			case "unobserved":
				req.TracePolicy.ObservedSymbol = func(artifacts.SymbolID) bool { return false }
			case "no observation callback":
				req.TracePolicy.ObservedSymbol = nil
			case "no quota callback":
				req.TracePolicy.TakeQuery = nil
			}
			res := h.Run(context.Background(), req)
			if res.OK || engine.calls != 0 || db.calls != 0 || *taken != 0 {
				t.Fatalf("unobserved request reached execution: %+v engine=%d quota=%d", res, engine.calls, *taken)
			}
		})
	}
	// The specified sink is sufficient when it is an indexed definition
	// actually observed by this pass; the source remains uniquely bound.
	h, req, engine, _, _ := traceActionFixture(t)
	req.TracePolicy.ObservedSymbol = func(id artifacts.SymbolID) bool { return id == "cpp:entry.c:2:consume(int)" }
	if result := h.Run(context.Background(), req); !result.OK || engine.calls != 1 {
		t.Fatalf("observed sink rejected: %+v", result)
	}
}

func TestTraceTaintDefaultsAllParametersAndCachesWithoutQuota(t *testing.T) {
	h, req, engine, db, taken := traceActionFixture(t)
	first := h.Run(context.Background(), req)
	if !first.OK {
		t.Fatal(first.Error)
	}
	var view struct {
		FactRef  string `json:"fact_ref"`
		CacheHit bool   `json:"cache_hit"`
	}
	if err := json.Unmarshal([]byte(first.Output), &view); err != nil {
		t.Fatal(err)
	}
	if view.CacheHit || view.FactRef == "" || *taken != 1 {
		t.Fatalf("unexpected initial query state: %+v quota=%d", view, *taken)
	}
	var fact artifacts.ToolFact
	if err := runfs.ReadJSON(view.FactRef, &fact); err != nil {
		t.Fatal(err)
	}
	var meta taint.Result
	if err := json.Unmarshal(fact.Result, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Parameters.SourceParamIndex != -1 || strings.Contains(engine.query, "parameter.getIndex() =") {
		t.Fatal("omitted source_param_index did not mean all parameters")
	}
	quotaCalls := 0
	req.TracePolicy.TakeQuery = func() bool { quotaCalls++; return false }
	req.Args = json.RawMessage(`{"source_func":"entry","sink_func":"consume","max_paths":10,"max_hops":20}`)
	second := h.Run(context.Background(), req)
	if !second.OK {
		t.Fatal(second.Error)
	}
	if err := json.Unmarshal([]byte(second.Output), &view); err != nil {
		t.Fatal(err)
	}
	if !view.CacheHit || engine.calls != 1 || db.calls != 1 || quotaCalls != 0 {
		t.Fatalf("cache consumed quota or repeated execution: hit=%v engine=%d db=%d quota=%d", view.CacheHit, engine.calls, db.calls, quotaCalls)
	}
	req.Args = json.RawMessage(`{"source_func":"entry","source_param_index":0,"sink_func":"consume"}`)
	blocked := h.Run(context.Background(), req)
	if blocked.OK || !strings.Contains(blocked.Error, "budget exhausted") || engine.calls != 1 || quotaCalls != 1 {
		t.Fatalf("quota did not block new query: %+v", blocked)
	}
}

func TestTraceTaintZeroPathsAreNotSafety(t *testing.T) {
	h, req, engine, _, _ := traceActionFixture(t)
	engine.results = nil
	result := h.Run(context.Background(), req)
	if !result.OK {
		t.Fatal(result.Error)
	}
	if !strings.Contains(result.Output, "does NOT prove safety") || !strings.Contains(result.Output, `"total_paths":0`) {
		t.Fatalf("zero result omitted uncertainty: %s", result.Output)
	}
}

func TestTraceTaintLargePathSummaryStaysBounded(t *testing.T) {
	h, req, engine, _, _ := traceActionFixture(t)
	engine.results = nil
	for p := 0; p < 14; p++ {
		var steps []codeql.PathStep
		for hop := 0; hop < 30; hop++ {
			steps = append(steps, codeql.PathStep{Path: "entry.c", StartLine: hop + 1, Function: strings.Repeat("callee", 1000), Expression: strings.Repeat("input", 1000)})
		}
		steps[len(steps)-1].StartLine += p
		engine.results = append(engine.results, codeql.Result{Paths: [][]codeql.PathStep{steps}})
	}
	req.Args = json.RawMessage(`{"source_func":"entry","sink_func":"consume","max_paths":10,"max_hops":20}`)
	result := h.Run(context.Background(), req)
	if !result.OK {
		t.Fatal(result.Error)
	}
	if len(result.Output) > observationlimits.MaxBytes || !json.Valid([]byte(result.Output)) || !strings.Contains(result.Output, `"truncated":true`) {
		t.Fatalf("unbounded or invalid summary: bytes=%d", len(result.Output))
	}
	var view struct {
		FactRef       string `json:"fact_ref"`
		ReturnedPaths int    `json:"returned_paths"`
	}
	if err := json.Unmarshal([]byte(result.Output), &view); err != nil {
		t.Fatal(err)
	}
	var persisted artifacts.ToolFact
	if err := runfs.ReadJSON(view.FactRef, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Paths) != 14 || len(persisted.Paths[0]) != 30 || view.ReturnedPaths > 10 {
		t.Fatalf("display bounds destroyed persisted paths: paths=%d returned=%d", len(persisted.Paths), view.ReturnedPaths)
	}
}
