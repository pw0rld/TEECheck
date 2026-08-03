package repoindex

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// tableEngine answers each query file with a canned table, so the whole
// stage — capability accounting, degradation, schema validation — runs
// without a CodeQL binary.
type tableEngine struct {
	rows map[string][][]string
	errs map[string]error
}

func (e *tableEngine) QueryTable(_ context.Context, opts codeql.QueryTableOptions) ([][]string, error) {
	name := filepath.Base(opts.QueryFile)
	if err := e.errs[name]; err != nil {
		return nil, err
	}
	return e.rows[name], nil
}

// fullEngine answers every query the way the index fixture does.
func fullEngine() *tableEngine {
	return &tableEngine{rows: map[string][][]string{
		querySymbols: {
			{"load_pub_key", "core/loader.c", "14", "struct pub_key * key", "core"},
			{"helper", "core/loader.c", "6", "int v", "core"},
			{"helper", "core/other.c", "4", "int v", "core"},
		},
		queryCallEdges: {
			{"load_pub_key", "core/loader.c", "14", "struct pub_key * key",
				"helper", "core/loader.c", "6", "int v", "core/loader.c", "17"},
		},
		queryUnresolved: {
			{"dispatch", "core/dispatch.c", "17", "struct ops * o",
				"core/dispatch.c", "19", "call to expression", "indirect"},
		},
		// 4 = 3 + 1, and external + ambiguous stay within resolved: the
		// identities decodeCallSiteCounts checks.
		queryCallSiteCounts: {
			{"total", "4"}, {"resolved", "3"}, {"unresolved", "1"},
			{"external", "1"}, {"ambiguous", "0"},
		},
		queryFieldAccesses: {{"load_pub_key", "core/loader.c", "14", "struct pub_key * key", "pub_key.max_depth", "pub_key.max_depth"}},
	}}
}

// probeRun writes a manifest and returns a config pointing at it.
func probeRun(t *testing.T, repo, commit string) config.Config {
	t.Helper()
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "run-idx",
		RepoURL: repo, Commit: commit, LocalPath: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	return config.Config{RunDir: runDir, KnowledgeRoot: filepath.Join(t.TempDir(), "knowledge")}
}

func readFacts(t *testing.T, runDir string) artifacts.RepoFacts {
	t.Helper()
	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err != nil {
		t.Fatalf("the stage must write repo_facts: %v", err)
	}
	return facts
}

// readyDB is a provider over an already-built database, so a test can reach
// the query path without CodeQL.
type readyDB struct{ path string }

func (d readyDB) Ensure(context.Context, codedb.Scope) (string, error) { return d.path, nil }
func (d readyDB) Path(codedb.Scope) string                             { return d.path }
func (d readyDB) State(codedb.Scope) string                            { return codedb.StateReady }

// failingDB stands for a repository CodeQL cannot extract.
type failingDB struct{}

func (failingDB) Ensure(context.Context, codedb.Scope) (string, error) {
	return "", errors.New("create database: extractor found no compilable source")
}
func (failingDB) Path(codedb.Scope) string  { return "" }
func (failingDB) State(codedb.Scope) string { return codedb.StateAbsent }

// A repository CodeQL cannot extract must still produce an artifact that
// says so. Writing nothing would leave every downstream "no callers found"
// unreadable: it would look exactly like a repository whose callers are
// genuinely absent.
func TestRun_UnbuildableDatabaseIsStatedNotImplied(t *testing.T) {
	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	if err := Run(cfg, failingDB{}, fullEngine()); err != nil {
		t.Fatalf("an unbuildable database must not fail the stage: %v", err)
	}
	facts := readFacts(t, cfg.RunDir)
	if facts.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		t.Errorf("symbols = %q, want unavailable", facts.Capabilities.Symbols)
	}
	if !strings.Contains(facts.IndexNote, "extractor") {
		t.Errorf("index_note must name the cause, got %q", facts.IndexNote)
	}
	if len(facts.Capsules) != 0 {
		t.Error("no database means no capsules")
	}
}

// A run with no pinned revision has nothing to build a database from. It is
// a legitimate configuration, not a failure, and must say which it is.
func TestRun_NoPinnedRevisionDegradesWithItsReason(t *testing.T) {
	cfg := probeRun(t, "", "")
	if err := Run(cfg, readyDB{path: t.TempDir()}, fullEngine()); err != nil {
		t.Fatalf("a run with no pinned revision must not fail the stage: %v", err)
	}
	if note := readFacts(t, cfg.RunDir).IndexNote; !strings.Contains(note, "pinned repository") {
		t.Errorf("index_note = %q, want it to name the missing pin", note)
	}
}

func TestRun_BuildsTheIndexAndItsCapabilities(t *testing.T) {
	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	if err := Run(cfg, readyDB{path: t.TempDir()}, fullEngine()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts := readFacts(t, cfg.RunDir)

	if facts.Capabilities.Symbols != artifacts.CapabilityAvailable {
		t.Errorf("symbols = %q, want available", facts.Capabilities.Symbols)
	}
	// One unresolved call means the call graph has a known gap, whatever the
	// edge count says.
	if facts.Capabilities.DirectCalls != artifacts.CapabilityPartial {
		t.Errorf("direct_calls = %q, want partial — one call site is unresolved", facts.Capabilities.DirectCalls)
	}
	// Never available: memcpy, pointer aliasing and designated initializers
	// are all outside what a direct-assignment predicate can see.
	if facts.Capabilities.FieldAccesses != artifacts.CapabilityPartial {
		t.Errorf("field_accesses = %q, want partial", facts.Capabilities.FieldAccesses)
	}
	// Nothing here computes reachability under a build configuration.
	if facts.Capabilities.BuildReachability != artifacts.CapabilityUnavailable {
		t.Errorf("build_reachability = %q, want unavailable", facts.Capabilities.BuildReachability)
	}

	if len(facts.Capsules) != 3 {
		t.Errorf("capsules = %d, want one per symbol", len(facts.Capsules))
	}
	// The identity is on the COUNT, not on the list length: a CodeQL result
	// is a set, so two calls on one line with the same expression collapse
	// into one row. On OP-TEE the list holds 1,423 rows for 1,552 sites.
	if facts.TotalCallSites != facts.ResolvedCallSites+facts.UnresolvedCallSiteCount {
		t.Errorf("total %d != resolved %d + unresolved %d — the index cannot check its own coverage",
			facts.TotalCallSites, facts.ResolvedCallSites, facts.UnresolvedCallSiteCount)
	}
	if len(facts.UnresolvedCallSites) > facts.UnresolvedCallSiteCount {
		t.Errorf("the deduplicated list (%d) cannot exceed the count (%d)",
			len(facts.UnresolvedCallSites), facts.UnresolvedCallSiteCount)
	}
	// The edge list is a subset of the resolved calls: a call to a callee
	// with no definition in this tree is resolved but carries no edge.
	if len(facts.CallEdges) > facts.ResolvedCallSites {
		t.Errorf("edges %d exceed resolved call sites %d", len(facts.CallEdges), facts.ResolvedCallSites)
	}
}

// One failed query must not discard the queries that succeeded. A field
// access query that will not run does not make the symbol table untrue.
func TestRun_OneFailedQueryDegradesOnlyItsOwnCapability(t *testing.T) {
	eng := fullEngine()
	eng.errs = map[string]error{queryFieldAccesses: errors.New("query compile failed")}

	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	if err := Run(cfg, readyDB{path: t.TempDir()}, eng); err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts := readFacts(t, cfg.RunDir)

	if facts.Capabilities.Symbols != artifacts.CapabilityAvailable {
		t.Errorf("symbols = %q, want available — the symbol query succeeded", facts.Capabilities.Symbols)
	}
	if facts.Capabilities.FieldAccesses != artifacts.CapabilityUnavailable {
		t.Errorf("field_accesses = %q, want unavailable", facts.Capabilities.FieldAccesses)
	}
	if !strings.Contains(facts.IndexNote, queryFieldAccesses) {
		t.Errorf("index_note must name the query that failed, got %q", facts.IndexNote)
	}
	if len(facts.Capsules) != 3 {
		t.Errorf("capsules = %d — the symbols are still known even with no field data", len(facts.Capsules))
	}
}

// A call graph that was never built must not be reported as a partial one.
// Before the guard, a second query failure overwrote "unavailable" with
// "partial" unconditionally, and a consumer would read an empty caller list
// as weak-but-real evidence from a graph that does not exist.
func TestRun_ANeverBuiltCallGraphIsNotPartial(t *testing.T) {
	eng := fullEngine()
	eng.errs = map[string]error{
		queryCallEdges:  errors.New("edges boom"),
		queryUnresolved: errors.New("unresolved boom"),
	}
	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	if err := Run(cfg, readyDB{path: t.TempDir()}, eng); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readFacts(t, cfg.RunDir).Capabilities.DirectCalls; got != artifacts.CapabilityUnavailable {
		t.Errorf("direct_calls = %q, want unavailable — no call query ran at all", got)
	}
}

// Counts without a call graph are a precise-looking number for something
// that was never built. They must not survive on their own.
func TestRun_CountsDoNotOutliveTheCallGraph(t *testing.T) {
	eng := fullEngine()
	eng.errs = map[string]error{queryCallSiteCounts: errors.New("counts boom")}
	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	if err := Run(cfg, readyDB{path: t.TempDir()}, eng); err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts := readFacts(t, cfg.RunDir)
	if facts.Capabilities.DirectCalls != artifacts.CapabilityUnavailable {
		t.Errorf("direct_calls = %q, want unavailable without its own accounting", facts.Capabilities.DirectCalls)
	}
	if len(facts.CallEdges) != 0 || facts.TotalCallSites != 0 {
		t.Errorf("edges=%d total=%d — a graph whose gaps cannot be stated must not ship",
			len(facts.CallEdges), facts.TotalCallSites)
	}
}

// Losing the unresolved list is worse than it looks: without it the call
// graph's own gaps are unknown, so no caller list can be read as complete
// however many edges it holds.
func TestRun_MissingUnresolvedListDowngradesTheCallGraph(t *testing.T) {
	eng := fullEngine()
	eng.errs = map[string]error{queryUnresolved: errors.New("boom")}

	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	if err := Run(cfg, readyDB{path: t.TempDir()}, eng); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readFacts(t, cfg.RunDir).Capabilities.DirectCalls; got != artifacts.CapabilityPartial {
		t.Errorf("direct_calls = %q, want partial — the graph's gaps are unknown", got)
	}
}

// A schema violation is a pipeline error, not a degradation: the next stage
// was promised a shape and would not get it.
func TestRun_UnwritableArtifactIsAPipelineError(t *testing.T) {
	cfg := probeRun(t, "https://example.invalid/r", "abc123")
	// Make the context directory a file, so writing the artifact cannot work.
	if err := os.WriteFile(runfs.ContextDir(cfg.RunDir), []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run(cfg, readyDB{path: t.TempDir()}, fullEngine()); err == nil {
		t.Error("an unwritable artifact must fail the run, not be swallowed as a degradation")
	}
}
