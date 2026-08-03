package repoindex

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

// The queries are the layer every negative result in the index inherits its
// meaning from, and CodeQL upgrades and predicate edits can change what they
// match without changing what they return. A hand-run check proves they work
// today and nothing tomorrow.
//
// This is also the only place that can demonstrate UnresolvedCalls.ql
// matches anything at all: a real repository may legitimately have zero
// unresolved calls, so a live run cannot be the evidence.

var (
	fixtureOnce sync.Once
	fixtureDB   string
	fixtureErr  error
	// fixtureRoot outlives every test in the package. t.TempDir() would be
	// removed when the first test that touched it finished, taking the
	// shared database with it.
	fixtureRoot string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "teecheck-index-fixture-*")
	if err != nil {
		panic(err)
	}
	fixtureRoot = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

// fixtureDatabase builds the index fixture's database once per package run.
// Extraction is seconds for four small files, but not free, and every query
// test wants the same database.
func fixtureDatabase(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("codeql"); err != nil {
		t.Skip("codeql not on PATH")
	}
	root := repoRoot(t)
	fixtureOnce.Do(func() {
		fixtureDB = filepath.Join(fixtureRoot, "db")
		fixtureErr = codeql.New().CreateDatabase(context.Background(), codeql.CreateDBOptions{
			Language:   "cpp",
			SourceRoot: filepath.Join(root, "testdata", "index_fixture"),
			DBPath:     fixtureDB,
			BuildMode:  "none",
			Overwrite:  true,
		})
	})
	if fixtureErr != nil {
		t.Fatalf("build fixture database: %v", fixtureErr)
	}
	return fixtureDB
}

func runIndexQuery(t *testing.T, name string) [][]string {
	t.Helper()
	rows, err := codeql.New().QueryTable(context.Background(), codeql.QueryTableOptions{
		DBPath:    fixtureDatabase(t),
		QueryFile: filepath.Join(repoRoot(t), "codeql", "index", "cpp", name),
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return rows
}

// Two files each define a static helper. If they collapse into one symbol,
// every call edge to either is attributed to whichever definition won.
func TestSymbolsQuery_SeparatesSameNamedStatics(t *testing.T) {
	var helpers [][]string
	for _, r := range runIndexQuery(t, "Symbols.ql") {
		if r[0] == "helper" {
			helpers = append(helpers, r)
		}
	}
	if len(helpers) != 2 {
		t.Fatalf("found %d definitions named helper, want 2: %v", len(helpers), helpers)
	}
	if helpers[0][1] == helpers[1][1] {
		t.Errorf("both helpers reported in the same file %q", helpers[0][1])
	}
	// The module is the containing directory, not the file: a whole tree of
	// one-function modules would make the Planner's browse useless.
	for _, h := range helpers {
		if h[4] != "core" {
			t.Errorf("module = %q, want core (the directory, not the file)", h[4])
		}
	}
}

// A call through a function pointer has no statically known callee. It must
// be absent from the resolved edges — an edge invented for it would let a
// consumer believe the call graph is complete.
func TestCallEdgesQuery_ExcludesTheFunctionPointerCall(t *testing.T) {
	rows := runIndexQuery(t, "CallEdges.ql")
	if len(rows) == 0 {
		t.Fatal("no resolved edges at all — the query is not matching")
	}
	for _, r := range rows {
		if r[0] == "dispatch" {
			t.Errorf("dispatch calls only through a function pointer; it must have no resolved edge: %v", r)
		}
	}
	// The two real edges are still there, so the exclusion is not the query
	// matching nothing.
	found := map[string]bool{}
	for _, r := range rows {
		found[r[0]+"->"+r[4]] = true
	}
	for _, want := range []string{"load_pub_key->helper", "other_entry->helper"} {
		if !found[want] {
			t.Errorf("missing resolved edge %s: %v", want, rows)
		}
	}

	// Referential integrity: every end of every edge must be a definition
	// the Symbols query also reports. An edge to a declaration-only callee —
	// memcpy, say — would carry a callee_id pointing at nothing, and a
	// consumer resolving it would find no capsule and have no way to tell
	// that from a function with no behaviour recorded.
	defined := map[string]bool{}
	for _, sym := range runIndexQuery(t, "Symbols.ql") {
		defined[sym[0]+"|"+sym[1]+"|"+sym[2]] = true
	}
	for _, r := range rows {
		caller := r[0] + "|" + r[1] + "|" + r[2]
		callee := r[4] + "|" + r[5] + "|" + r[6]
		if !defined[caller] {
			t.Errorf("edge caller %s is not in the symbol table", caller)
		}
		if !defined[callee] {
			t.Errorf("edge callee %s is not in the symbol table — a callee_id pointing at nothing", callee)
		}
	}
}

// The complement: the unresolved call must actually be reported, with enough
// context to ask whether it could reach a given function.
func TestUnresolvedCallsQuery_ReportsTheFunctionPointerCall(t *testing.T) {
	rows := runIndexQuery(t, "UnresolvedCalls.ql")
	if len(rows) != 1 {
		t.Fatalf("unresolved calls = %d, want exactly the one in dispatch: %v", len(rows), rows)
	}
	r := rows[0]
	if r[0] != "dispatch" {
		t.Errorf("enclosing function = %q, want dispatch", r[0])
	}
	if r[4] != "core/dispatch.c" {
		t.Errorf("call file = %q, want core/dispatch.c", r[4])
	}
	if r[7] != "indirect" {
		t.Errorf("resolution kind = %q, want indirect", r[7])
	}
}

// The distinction the two columns exist for. fill_version copies into
// key->version with memcpy: both fields are touched, neither is the target
// of an assignment expression, so an absent write must not read as "never
// written".
func TestFieldAccessesQuery_SeparatesAccessesFromDirectWrites(t *testing.T) {
	byFunc := map[string][]string{}
	for _, r := range runIndexQuery(t, "FieldAccesses.ql") {
		byFunc[r[0]] = r
	}

	fill, ok := byFunc["fill_version"]
	if !ok {
		t.Fatalf("fill_version missing from the index: %v", byFunc)
	}
	for _, want := range []string{"pub_key.version", "subkey.subkey_version"} {
		if !strings.Contains(fill[4], want) {
			t.Errorf("fill_version accesses = %q, want it to contain %q", fill[4], want)
		}
	}
	if fill[5] != "" {
		t.Errorf("fill_version direct_writes = %q, want empty — memcpy is not an assignment expression", fill[5])
	}

	load, ok := byFunc["load_pub_key"]
	if !ok {
		t.Fatalf("load_pub_key missing from the index: %v", byFunc)
	}
	if !strings.Contains(load[4], "pub_key.max_depth") || !strings.Contains(load[4], "subkey.max_depth") {
		t.Errorf("load_pub_key accesses = %q, want both max_depth fields", load[4])
	}
	if load[5] != "pub_key.max_depth" {
		t.Errorf("load_pub_key direct_writes = %q, want exactly pub_key.max_depth", load[5])
	}
	// The shape CVE-2026-44362 has, stated as facts and nothing more: a
	// field read by one function and written by no one.
	if strings.Contains(load[5], "pub_key.version") {
		t.Error("pub_key.version is never assigned in the fixture; reporting a write for it would be wrong")
	}
}
