# Program Index and Planner-Driven Reconnaissance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the deleted keyword fingerprint with a deterministic whole-repo program index, expose it to the Planner as a browsable project map, and make the Planner produce structured `AuditLead`s from a project-first reconnaissance pass that is not primed by TWE, Architecture or pre-existing invariants.

**Architecture:** BUG-003 Phase 1 + Phase 2, against the contracts in `tee-usage-scanner/docs/ARCHITECTURE.md` §5 (Program Index), §6 (Planner-Driven Reconnaissance), §7 (EvidenceSlice and negative evidence). `01A repoIndex` builds `repo_facts.v1.json` from the CodeQL database. `01B projectMap` derives a neutral navigation view and pre-writes the function-card pages. The Planner runs ORIENT → MAP → LEAD, emitting `AuditLead`s and a `CoverageLedger`. Pass A carries no TWE/Architecture/Invariant priming; `twe_playbook_detail` opens only in Pass B, after the first lead.

**Tech Stack:** Go, CodeQL CLI (already on PATH), a new query pack under `tee-usage-scanner/codeql/index/cpp`, a new `internal/codedb` shared database manager. No new Go dependencies.

## Scope

Covers BUG-003 **Phase 1 and Phase 2**.

Phase 3 (`formalize_invariant`, `CaseInvariantV2`, `InvariantAssessment`) and Phase 4 (SecurityArchitecture write-back) get their own plan. The dependency is real: BUG-003's generation condition #2 for a Case Invariant is *"至少读取了相关函数或取得等价的 CodeQL 事实"*, and that is only mechanically checkable once the `AuditLead.reason_fact_refs` contract from Task 8 exists, which in turn needs the observation references from Task 7.

**This plan does not move `architecture.Run` or `invariants.Run`.** Both keep running where they are so their artifacts stay available to the existing downstream review chain. What changes is that the Planner stops *reading* them. Moving the stages themselves is Phase 4 — attempting it here would mean rewriting the expert/challenger/verifier context loaders in the same change as the index, and a failure would be untraceable to either.

## Measured baselines

Taken 2026-08-02 against `runs/run-b`'s CodeQL database for `OP-TEE/optee_os@a9386bf987d9` (322 MB, 3291 files). Expect these; investigate a >2× deviation.

Corrected 2026-08-03 after a review found the queries were emitting a cross
product; the first numbers here were measured against that defect.

```text
distinct function definitions            11,603
call sites                               42,317
  resolved (target nameable)             40,765
    -> one in-tree definition (an edge)   35,424
    -> callee not defined in tree          3,458
    -> callee defined several times        1,883
  unresolved (no target at all)            1,552
fields                                   10,301

query evaluation, whole repo    1-3 s each after compile
capsule JSON total                6.36 MB
per capsule       avg 340 B / median 225 B / p90 734 B / max 26 KB
```

Two identities hold exactly and are checked in Go:

```text
total 42,317 = resolved 40,765 + unresolved 1,552
resolved     = edges 35,424 + external 3,458 + ambiguous 1,883
```

The LISTS are shorter than the counts, and deliberately so: a CodeQL result
is a set, so two calls on one line with the same expression collapse. The
unresolved list holds 1,423 rows for 1,552 sites, and the edge list 34,329
for 35,424. Any check must be on the counts.

Consequences the tasks encode:

1. Whole-repo indexing is affordable. Do not build a "which functions are worth indexing" selector.
2. 6.36 MB cannot enter a prompt, and the 26 KB maximum means a page cap must be in **bytes**, not lines.

## Global Constraints

- **01 must not decide where the danger is.** No artifact this plan produces may carry a priority, risk score, vulnerability label or TWE mapping. A capsule field named anything like `suspicious`, `candidate`, `risk`, `severity` is a plan violation (Task 1 tests for it). BUG-003 §3.3 traces what happens when 01 pre-judges.
- **Pass A carries no priors.** During reconnaissance the Planner's system prompt gets `PriorKnowledge{}` — no TWE catalog, no ArchitectureModel, no ProjectInvariants, no obligations block. A model shown the old invariants first will anchor on them and browse five functions for form's sake.
- **Field names must mean what they say.** CodeQL's `FieldAccess` covers the left-hand side of an assignment too, so a naive "reads" predicate silently includes writes. The index exposes `field_accesses` and `direct_field_writes`, never `reads_fields`.
- **Negative results carry their capability and scope**, using the ARCHITECTURE.md §7 ladder: `not_found_in_snippet` / `not_found_in_file` / `not_found_in_partial_scope` / `not_found_in_indexed_repository` / `proved_unreachable_under_build_target`. Nothing writes a bare "not found".
- **Index availability is per capability, not global.** `--build-mode=none` plus unresolved calls means "symbols available, direct_calls partial, build_reachability unavailable". A single `complete` invites over-trust.
- **Symbols have stable IDs.** `(file, symbol)` is not an identity in C/C++: two files can hold same-named `static` functions and one file can hold C++ overloads. Every capsule, call edge and lead reference uses `SymbolID`.
- **The CodeQL database is built once per run**, by `internal/codedb`, and shared with `internal/trustirfacts`. No task may add a second build.
- **A missing database is never fatal.** The run degrades to `tree_only` reconnaissance, and says so in the artifacts.
- **Deletions are real deletions**, not feature flags.
- **Paths are constants, never string literals.** The query pack lives at `tee-usage-scanner/codeql/index/cpp/`, beside the existing `tee-usage-scanner/codeql/trustir/cpp/`. Run artifacts are reached **only** through `runfs` helpers — `runfs.PlannerDir`, `runfs.RoundsLogPath`, `runfs.AuditLeadsPath`, `runfs.CoverageLedgerPath`. This plan does not renumber the run directory: ARCHITECTURE.md §11 moves the planner to `03_planner`, the helpers today resolve to `04_planner`, and the renumber is a separate atomic change. No number appears in any new code or in any test assertion, so that change stays a one-file edit.
- `go test ./...`, `gofmt -l internal cmd`, `go vet ./...` green at the end of every task. Every task ends with a commit.

---

## Task 0: Shared database manager and a table-query interface

The existing `codeql.Engine.Analyze` runs `codeql database analyze --format=sarifv2.1.0` (`internal/codeql/engine.go:189`) and parses findings out of SARIF. It cannot return an arbitrary eight-column table. Separately, `trustirfacts.databaseDir` and `trustirfacts.ensureDatabase` are package-private (`internal/trustirfacts/db.go:43`, `:128`), so nothing outside that package can locate or build the run's database. Both have to be fixed before any indexing code can be written.

**Files:**
- Create: `tee-usage-scanner/internal/codedb/manager.go`
- Create: `tee-usage-scanner/internal/codedb/doc.go`
- Test: `tee-usage-scanner/internal/codedb/manager_test.go`
- Modify: `tee-usage-scanner/internal/codeql/engine.go`
- Test: `tee-usage-scanner/internal/codeql/table_test.go`
- Modify: `tee-usage-scanner/internal/trustirfacts/db.go`

**Interfaces:**
- Produces: `codeql.QueryTableOptions{DBPath, QueryFile, ExtraPATH string; Timeout time.Duration}`
- Produces: `func (e *Engine) QueryTable(ctx context.Context, opts QueryTableOptions) ([][]string, error)`
- Produces: `type codedb.Scope struct { RunDir, Repository, Commit string }`
- Produces: `type codedb.Manager` with `Ensure(ctx, scope) (string, error)`, `Path(scope) string`, `State(scope) State`
- Produces: `type codedb.DatabaseProvider interface { Ensure(context.Context, Scope) (string, error); Path(Scope) string }` — the seam both consumers take
- Modifies: `trustirfacts.Run` / `RunAndPersist` to accept a `codedb.DatabaseProvider` and stop resolving the database themselves

The provider interface is the point of this task, not a decoration. `trustirfacts.Run(ctx, eng, req)` currently resolves and builds its own database from private helpers; if the migration only moves those functions into `codedb`, the two packages still each manage a database and the "built once per run" constraint is unenforced. Both call sites must end up holding the *same provider value*, threaded from `pipeline.RunWithClient`.

- [ ] **Step 1: Write the failing table-query test**

```go
package codeql

import (
	"context"
	"strings"
	"testing"
)

// The index needs arbitrary tables, and Analyze cannot give them: it shells
// out to `database analyze --format=sarifv2.1.0` and reads findings back out
// of SARIF, a shape with no room for an eight-column result.
func TestQueryTable_RejectsAMissingDatabaseWithoutShellingOut(t *testing.T) {
	e := NewWithBin("/nonexistent/codeql")
	_, err := e.QueryTable(context.Background(), QueryTableOptions{
		DBPath: t.TempDir(), QueryFile: "nope.ql",
	})
	if err == nil {
		t.Fatal("a missing query file must fail before the subprocess")
	}
	if !strings.Contains(err.Error(), "nope.ql") {
		t.Errorf("the error must name what was missing: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/codeql/ -run TestQueryTable -v`
Expected: FAIL — `undefined: QueryTableOptions`

- [ ] **Step 3: Implement QueryTable**

Two subprocess calls, both through the same executor path `run` already uses so they emit `tool_call_*` events like every other tool:

```go
// QueryTableOptions runs one query for its result table rather than for
// findings.
type QueryTableOptions struct {
	DBPath    string
	QueryFile string
	ExtraPATH string
	Timeout   time.Duration
}

// QueryTable evaluates a @kind table query and returns its rows as strings.
//
// Analyze cannot serve this: it runs `database analyze --format=sarifv2.1.0`
// and reads findings out of SARIF, which has a place for a message and a
// location and nowhere to put an eight-column row. The program index is not
// a set of findings — it is a table — so it needs its own path:
//
//	codeql query run --database=<db> --output=<tmp>.bqrs <query>
//	codeql bqrs decode --format=json --result-set='#select' <tmp>.bqrs
//
// Every value is returned as a string. The caller knows its own column
// types; a shared decoder that guessed them would be one more place for the
// query and the Go code to disagree silently.
func (e *Engine) QueryTable(ctx context.Context, opts QueryTableOptions) ([][]string, error) {
	if _, err := os.Stat(opts.QueryFile); err != nil {
		return nil, fmt.Errorf("codeql query table: query file %s: %w", opts.QueryFile, err)
	}
	// ... query run --output=bqrs, then bqrs decode --format=json,
	// then walk result["#select"]["tuples"] and fmt.Sprint each cell.
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd tee-usage-scanner && go test ./internal/codeql/ -v`
Expected: PASS

- [ ] **Step 5: Write the failing manager test**

```go
package codedb

import "testing"

// Two packages needing the same database must not each build one. The path
// is derived from (repository, commit) so both compute the same answer
// without coordinating.
func TestManager_PathIsStableForTheSameRevision(t *testing.T) {
	runDir := t.TempDir()
	m := New(nil, nil)
	a := m.Path(Scope{RunDir: runDir, Repository: "https://github.com/OP-TEE/optee_os", Commit: "a9386bf"})
	b := m.Path(Scope{RunDir: runDir, Repository: "https://github.com/OP-TEE/optee_os.git", Commit: "a9386bf"})
	if a != b {
		t.Errorf("the same revision must resolve to one database, got\n%s\n%s", a, b)
	}
}

func TestManager_StateReportsAbsentBeforeAnyBuild(t *testing.T) {
	m := New(nil, nil)
	if got := m.State(Scope{RunDir: t.TempDir(), Repository: "r", Commit: "c"}); got != StateAbsent {
		t.Errorf("State = %q, want %q", got, StateAbsent)
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/codedb/ -v`
Expected: FAIL — no such package.

- [ ] **Step 7: Write the manager**

Move `dbDirName`, `databaseDir`, `ensureSource`, `srcClonedMarker` and the build-completion marker out of `internal/trustirfacts/db.go` into `internal/codedb`, exported. `Ensure` is idempotent and safe to call from both packages; `State` returns `StateAbsent` / `StateBuilding` / `StateReady` / `StateFailed` from the on-disk markers.

- [ ] **Step 8: Repoint trustirfacts at the provider**

`trustirfacts.Run` and `RunAndPersist` grow a `codedb.DatabaseProvider` parameter and delete their own resolution path. `go test ./internal/trustirfacts/...` must stay green apart from the signature change at the call sites — if a trustirfacts test's *expectations* need editing, the move changed behaviour and that is a defect, not a migration cost.

Verify the constraint mechanically rather than by reading: after Task 5 wires the pipeline, a full run's event stream must contain exactly one `codeql-database-create`.

```bash
python3 -c "
import json,sys,collections
c=collections.Counter()
for l in open(sys.argv[1]):
    e=json.loads(l)
    if e.get('tool_name')=='codeql-database-create': c[e.get('agent')]+=1
print(dict(c))
" runs/<run-id>/events.jsonl
```

Expected: `{'repo-index': 1}`.

- [ ] **Step 9: Run everything**

Run: `cd tee-usage-scanner && go test ./... && gofmt -l internal cmd && go vet ./...`
Expected: green.

- [ ] **Step 10: Commit**

```bash
git add tee-usage-scanner/internal/codedb/ tee-usage-scanner/internal/codeql/ tee-usage-scanner/internal/trustirfacts/
git commit -m "codedb,codeql: share the database and add a table-query path"
```

---

## Task 1: Index contracts — SymbolID, CallEdge, RepoFacts, ProjectMap, and their schemas

**Files:**
- Create: `tee-usage-scanner/internal/artifacts/index_types.go`
- Test: `tee-usage-scanner/internal/artifacts/index_types_test.go`
- Create: `schemas/repo-facts.v1.json`
- Create: `schemas/project-map.v1.json`
- Create: `tee-usage-scanner/internal/schema/schemas/repo-facts.v1.json` (byte-identical copy)
- Create: `tee-usage-scanner/internal/schema/schemas/project-map.v1.json` (byte-identical copy)
- Modify: `tee-usage-scanner/internal/schema/schema.go`

**Interfaces:**
- Produces: `artifacts.SymbolID` (string alias), `func artifacts.MakeSymbolID(lang, file string, line int, name, signature string) SymbolID`
- Produces: `artifacts.Symbol`, `artifacts.CallEdge`, `artifacts.UnresolvedCall`, `artifacts.FunctionCapsule`, `artifacts.RepoFacts`, `artifacts.IndexCapabilities`
- Produces: `artifacts.ProjectMap`, `artifacts.RepositoryCard`, `artifacts.ModuleCard`, `artifacts.FunctionCardPageRef`
- Produces: `schema.RepoFactsV1`, `schema.ProjectMapV1` registered in `schema.All`

- [ ] **Step 1: Write the failing test**

```go
package artifacts

import (
	"encoding/json"
	"strings"
	"testing"
)

// (file, symbol) is not an identity in C/C++: two files can each hold a
// static function of the same name, and one C++ file can hold overloads.
// A map keyed on the bare name connects call edges to the wrong definition.
func TestMakeSymbolID_SeparatesSameNamedDefinitions(t *testing.T) {
	a := MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 262, "load", "(struct shdr*)")
	b := MakeSymbolID("cpp", "core/kernel/ree_fs_ta.c", 262, "load", "(struct shdr*)")
	c := MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 262, "load", "(int)")
	if a == b {
		t.Error("same name in different files must not share an id")
	}
	if a == c {
		t.Error("overloads in one file must not share an id")
	}
}

// 01 must not decide where the danger is. A judgement field here would
// reintroduce BUG-003 §3.3's amplification chain under a new name.
func TestFunctionCapsule_CarriesNoVerdictFields(t *testing.T) {
	data, err := json.Marshal(FunctionCapsule{SymbolID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	typ := strings.ToLower(string(data))
	for _, banned := range []string{"risk", "priority", "candidate", "suspicious", "severity", "twe"} {
		if strings.Contains(typ, banned) {
			t.Errorf("FunctionCapsule carries a judgement field containing %q", banned)
		}
	}
}

// CodeQL's FieldAccess covers the left-hand side of an assignment, so a
// predicate named "reads" silently includes writes. The name has to match
// what the query can actually prove.
func TestFunctionCapsule_FieldNamesMatchWhatIsProved(t *testing.T) {
	data, _ := json.Marshal(FunctionCapsule{})
	if strings.Contains(string(data), "reads_fields") {
		t.Error("reads_fields is a lie — FieldAccess includes assignment targets; use field_accesses")
	}
}

// Every capsule states the limits of its own lists, so a consumer cannot
// read "no callers" as "never called".
func TestFunctionCapsule_DeclaresItsScopes(t *testing.T) {
	c := FunctionCapsule{}
	if c.CallersScope() != ScopeDirectResolvedCallsOnly {
		t.Errorf("CallersScope = %q", c.CallersScope())
	}
	if c.FieldWritesScope() != ScopeDirectAssignmentOnly {
		t.Errorf("FieldWritesScope = %q", c.FieldWritesScope())
	}
}

// One global "complete" invites over-trust: with --build-mode=none the
// symbols are solid while build reachability was never computed at all.
func TestIndexCapabilities_ArePerCapability(t *testing.T) {
	caps := IndexCapabilities{
		Symbols: CapabilityAvailable, DirectCalls: CapabilityPartial,
		FieldAccesses: CapabilityPartial, BuildReachability: CapabilityUnavailable,
	}
	data, _ := json.Marshal(caps)
	for _, want := range []string{"symbols", "direct_calls", "build_reachability"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("capabilities JSON missing %q: %s", want, data)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/artifacts/ -run "SymbolID|Capsule|Capabilities" -v`
Expected: FAIL — `undefined: MakeSymbolID`

- [ ] **Step 3: Write the types**

```go
package artifacts

const (
	SchemaVersionRepoFactsV1  = "teecheck.repo_facts.v1"
	SchemaVersionProjectMapV1 = "teecheck.project_map.v1"
)

// Capability states per index capability. A single global "complete" is a
// trap: with --build-mode=none the symbol table is solid, the call graph is
// missing every indirect edge, and build reachability was never computed.
// A consumer that sees one word cannot tell which of those it is holding.
const (
	CapabilityAvailable   = "available"
	CapabilityPartial     = "partial"
	CapabilityUnavailable = "unavailable"
)

// Scope strings a capsule's lists carry, so "no callers" is never read as
// "never called". They are the ARCHITECTURE.md §7 vocabulary applied to the
// index's own limits.
const (
	ScopeDirectResolvedCallsOnly = "direct_resolved_calls_only"
	ScopeDirectAssignmentOnly    = "direct_assignment_only"
)

// SymbolID is a stable identity for one definition.
//
// (file, symbol) is not enough for C/C++: two files can each define a static
// function of the same name, and one C++ translation unit can hold
// overloads. The Planner searches by name, gets candidates, and then asks
// for a specific id — so ambiguity is surfaced to the model instead of being
// resolved arbitrarily by a map write.
type SymbolID string

// MakeSymbolID builds the id. Signature is included because it is the only
// thing separating overloads; file and line separate same-named statics.
func MakeSymbolID(lang, file string, line int, name, signature string) SymbolID {
	return SymbolID(fmt.Sprintf("%s:%s:%d:%s%s", lang, file, line, name, signature))
}

type Symbol struct {
	SymbolID      SymbolID `json:"symbol_id"`
	Name          string   `json:"name"`
	QualifiedName string   `json:"qualified_name,omitempty"`
	File          string   `json:"file"`
	StartLine     int      `json:"start_line"`
	Signature     string   `json:"signature,omitempty"`
	Module        string   `json:"module,omitempty"`
}

// CallEdge is one resolved call. Keeping edges separate from capsules is
// what lets a caller list be reconstructed by id rather than by name.
type CallEdge struct {
	CallerID   SymbolID `json:"caller_id"`
	CalleeID   SymbolID `json:"callee_id"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Resolution string   `json:"resolution"` // "direct"
}

// UnresolvedCall is one call site whose target the extractor could not name.
//
// A total count is not enough. "Does anything unresolved reach
// shdr_load_pub_key?" cannot be answered from a number, so a missing caller
// stays weak evidence no matter how small the count is. The enclosing symbol
// and the call expression are what make the question answerable.
type UnresolvedCall struct {
	EnclosingSymbolID SymbolID `json:"enclosing_symbol_id,omitempty"`
	File              string   `json:"file"`
	Line              int      `json:"line"`
	Expression        string   `json:"expression,omitempty"`
	ResolutionKind    string   `json:"resolution_kind"` // "indirect" | "macro" | "unknown"
}

// FunctionCapsule is one function's neutral behaviour record. No priority,
// no risk label, no TWE mapping — see this plan's global constraints.
type FunctionCapsule struct {
	SymbolID SymbolID `json:"symbol_id"`
	Name     string   `json:"name"`
	Module   string   `json:"module"`
	File     string   `json:"file"`
	Line     int      `json:"line"`

	CalledBy []SymbolID `json:"called_by,omitempty"`
	Calls    []SymbolID `json:"calls,omitempty"`

	// FieldAccesses is every "Type.field" the function touches, read or
	// written: CodeQL's FieldAccess covers an assignment's left-hand side,
	// so it cannot be called "reads".
	FieldAccesses []string `json:"field_accesses,omitempty"`
	// DirectFieldWrites is the subset provable as a direct assignment. A
	// field filled by memcpy, through a pointer alias, or by a designated
	// initializer is absent here and its absence proves nothing.
	DirectFieldWrites []string `json:"direct_field_writes,omitempty"`
}

func (FunctionCapsule) CallersScope() string     { return ScopeDirectResolvedCallsOnly }
func (FunctionCapsule) FieldWritesScope() string { return ScopeDirectAssignmentOnly }

type IndexCapabilities struct {
	Symbols           string `json:"symbols"`
	DirectCalls       string `json:"direct_calls"`
	FieldAccesses     string `json:"field_accesses"`
	BuildReachability string `json:"build_reachability"`
}

type RepoFacts struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Scope         ScannedScope      `json:"scope"`
	Capabilities  IndexCapabilities `json:"capabilities"`
	IndexNote     string            `json:"index_note,omitempty"`

	Languages    []string `json:"languages,omitempty"`
	BuildTargets []string `json:"build_targets,omitempty"`

	Symbols  []Symbol          `json:"symbols,omitempty"`
	Capsules []FunctionCapsule `json:"capsules,omitempty"`

	// CallEdges is the resolved call graph, kept whole rather than only as
	// the per-capsule caller/callee lists. projectmap derives module
	// dependency edges from it, and doing that from the capsule lists alone
	// would mean resolving callee names back to definitions — the exact
	// name-to-definition guess SymbolID exists to prevent.
	CallEdges []CallEdge `json:"call_edges,omitempty"`

	TotalCallSites      int              `json:"total_call_sites"`
	ResolvedCallSites   int              `json:"resolved_call_sites"`
	UnresolvedCallSites []UnresolvedCall `json:"unresolved_call_sites,omitempty"`
}
```

`ProjectMap`, `RepositoryCard`, `ModuleCard` and `FunctionCardPageRef` as in the previous revision, with two changes: `ModuleCard.CallsModules` / `CalledByModules` are derived from `CallEdge` by id, never by name; and `FunctionCardPageRef` gains `Path string` naming the pre-written page file (Task 4).

- [ ] **Step 4: Write both JSON schemas and register them**

`schemas/repo-facts.v1.json` requires `schema_version` (const), `run_id`, `scope`, `capabilities`, and each capability constrained to the three-value enum. It sets `"additionalProperties": false` on the capsule object — that is what makes the "no judgement fields" constraint a cross-stage contract rather than a Go-only test.

`schemas/project-map.v1.json` likewise. Copy both byte-identical into `internal/schema/schemas/`, add `RepoFactsV1` / `ProjectMapV1` to the `Name` constants and to `schema.All`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/artifacts/ ./internal/schema/ -v 2>&1 | tail -20`
Expected: PASS, including `TestCanonicalDirHasExactlyEmbeddedSchemas`.

- [ ] **Step 6: Commit**

```bash
git add schemas/ tee-usage-scanner/internal/artifacts/ tee-usage-scanner/internal/schema/
git commit -m "artifacts,schema: add the program index and project map contracts"
```

---

## Task 2: CodeQL index queries, validated against a fixture with an indirect call

**Files:**
- Create: `tee-usage-scanner/codeql/index/cpp/qlpack.yml`
- Create: `tee-usage-scanner/codeql/index/cpp/Symbols.ql`
- Create: `tee-usage-scanner/codeql/index/cpp/CallEdges.ql`
- Create: `tee-usage-scanner/codeql/index/cpp/FieldAccesses.ql`
- Create: `tee-usage-scanner/codeql/index/cpp/UnresolvedCalls.ql`
- Create: `tee-usage-scanner/testdata/index_fixture/` (a small C project with a function pointer call)

**Interfaces:**
- Produces: four `@kind table` queries with fixed column orders, documented in each query's header, consumed by Task 3.

- [ ] **Step 1: Write the fixture**

A handful of `.c`/`.h` files containing: two same-named `static` functions in different files, one function whose field is written by direct assignment, one written via `memcpy`, and one call made through a function pointer. This fixture is what proves the unresolved query actually matches something — the acceptance criterion cannot be "the count is non-zero on a real repo", because a legitimate repository may have zero.

- [ ] **Step 2: Write the four queries**

Gotchas, both of which cost time if rediscovered: `module` is a QL keyword and cannot be a `select` alias; `concat` aggregates must be bound in `where` when the query also selects them.

`FieldAccesses.ql` emits two columns per function — every access, and the direct-assignment subset — so the Go side never has to infer one from the other:

```ql
/**
 * @name Field accesses and direct field writes
 * @description Per function: every struct field it touches, and the subset
 *              provable as a direct assignment.
 *
 *              These are two columns rather than one because CodeQL's
 *              FieldAccess matches an assignment's left-hand side too. A
 *              single "reads" column would silently contain writes, and a
 *              consumer comparing a producer's reads against a consumer's
 *              reads would be comparing the wrong sets.
 *
 *              direct_writes misses memcpy into a struct, writes through a
 *              pointer alias, and designated initializers. Its absence is
 *              never proof that a field is unwritten.
 * @kind table
 * @id teecheck/index/field-accesses
 */
```

- [ ] **Step 3: Write an automated fixture test for the queries**

Create `tee-usage-scanner/internal/repoindex/query_fixture_test.go`, skipped with `t.Skip` when `codeql` is not on PATH so it does not break a machine without the CLI. It builds a database from `testdata/index_fixture` once per package run and asserts:

- `Symbols.ql` returns the two same-named statics as distinct rows with distinct files
- `CallEdges.ql` does **not** contain the function-pointer call
- `UnresolvedCalls.ql` returns exactly that call, with its enclosing symbol and line
- `FieldAccesses.ql` lists the memcpy-filled field in the access column and **not** in the direct-writes column

A hand-run check would prove the queries work today and prove nothing tomorrow: a CodeQL upgrade or a predicate edit can silently change what these match, and every downstream negative result inherits that change. This test is also the acceptance evidence that `UnresolvedCalls.ql` matches anything at all — a real repository may legitimately have zero unresolved calls, so a live run cannot demonstrate it.

- [ ] **Step 4: Verify on the real database**

Run all four against `runs/run-b`'s database. Expected: capsule-shaped output in the seconds, ~11,300 distinct symbols.

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/codeql/index/cpp/ tee-usage-scanner/testdata/index_fixture/
git commit -m "codeql: add the neutral program index queries and their fixture"
```

---

## Task 3: repoindex

**Files:**
- Create: `tee-usage-scanner/internal/repoindex/run.go`
- Create: `tee-usage-scanner/internal/repoindex/decode.go`
- Create: `tee-usage-scanner/internal/repoindex/doc.go`
- Test: `tee-usage-scanner/internal/repoindex/decode_test.go`
- Test: `tee-usage-scanner/internal/repoindex/run_test.go`

**Interfaces:**
- Consumes: `codedb.Manager` (Task 0), `codeql.Engine.QueryTable` (Task 0), the contracts from Task 1
- Produces: `func Run(cfg config.Config, db *codedb.Manager, eng codeql.TableQuerier) error` writing `01_context/repo_facts.v1.json`
- Produces: `func buildCapsules(symbols []artifacts.Symbol, edges []artifacts.CallEdge, accesses map[artifacts.SymbolID][2][]string) []artifacts.FunctionCapsule`

- [ ] **Step 1: Write the failing decode tests**

Cover: dedupe of header duplicates by `SymbolID`; caller/callee lists assembled from `CallEdge` by id so two same-named functions do not merge; empty columns decoding to no entries; `total = resolved + unresolved` consistency.

- [ ] **Step 2: Run to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/repoindex/ -v`
Expected: FAIL — no such package.

- [ ] **Step 3: Write the decoder and the stage**

Every failure path writes the artifact with the affected capability set to `unavailable` and a note naming the cause, and returns nil:

```go
// Run builds the whole-repo program index.
//
// Two error classes, deliberately distinguished. A repository CodeQL cannot
// extract is a DEGRADATION: repo_facts.v1.json is still written, with the
// affected capabilities "unavailable" and a note naming the cause, and Run
// returns nil. The alternative — no artifact — makes every downstream
// negative result unreadable, because "no callers found" and "no index
// existed" look identical to a consumer with nothing to check.
//
// A schema validation failure or an unwritable artifact is a PIPELINE ERROR
// and returns non-nil. Swallowing those would let the run continue against a
// contract nobody upheld, which is worse than stopping: the stages after
// this one would read a file whose shape they were promised and did not get.
func Run(cfg config.Config, db codedb.DatabaseProvider, eng codeql.TableQuerier) error
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/repoindex/ -v`

- [ ] **Step 5: Fire drill**

Make the failure path write `CapabilityAvailable`; confirm the unavailable-path test FAILS. Restore.

- [ ] **Step 6: Commit**

```bash
git add tee-usage-scanner/internal/repoindex/
git commit -m "repoindex: build the whole-repo program index"
```

---

## Task 4: projectmap, with pre-written function card pages

**Files:**
- Create: `tee-usage-scanner/internal/projectmap/run.go`
- Create: `tee-usage-scanner/internal/projectmap/cards.go`
- Test: `tee-usage-scanner/internal/projectmap/cards_test.go`
- Modify: `tee-usage-scanner/internal/runfs/scope.go` (add `FunctionCardsDir`)

**Interfaces:**
- Consumes: `artifacts.RepoFacts`
- Produces: `func Run(cfg config.Config) error` writing `01_context/project_map.v1.json` **and** `01_context/function_cards/<module>/<page>.json`
- Consumes: `observationlimits.MaxBytes` (Task 7 declares it; Task 4 must not declare its own)

- [ ] **Step 1: Write the failing test**

Cover: per-module file and function counts (the `lib/libmbedtls` 898-file case the deleted fingerprint never reported); module edges derived from `CallEdge` by id; **pages split by byte budget, not by a fixed count** — a page holding one 26 KB capsule and a page holding 200 small ones are both legal, and both must stay under `observationlimits.MaxBytes`; `FunctionCardPageRef.Path` pointing at a file that exists.

```go
// The baseline measured a 26 KB capsule. A fixed 50-per-page split would put
// several of those in one observation; the cap has to be on bytes.
func TestPaginate_SplitsByBytesNotCount(t *testing.T) {
	big := strings.Repeat("x", 20*1024)
	caps := []artifacts.FunctionCapsule{
		{SymbolID: "a", Name: big}, {SymbolID: "b", Name: big}, {SymbolID: "c", Name: big},
	}
	pages := paginate(caps)
	if len(pages) < 2 {
		t.Fatalf("three 20 KB capsules must not share one page, got %d page(s)", len(pages))
	}
	for i, p := range pages {
		if n := pageBytes(p); n > observationlimits.MaxBytes {
			t.Errorf("page %d is %d bytes, over the %d cap", i, n, observationlimits.MaxBytes)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**; **Step 3: implement**; **Step 4: verify it passes**

Pre-writing pages is what keeps `list_functions` from deserialising the whole 6.36 MB `repo_facts.v1.json` on every call.

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/projectmap/ tee-usage-scanner/internal/runfs/
git commit -m "projectmap: derive the navigation view and pre-write its pages"
```

---

## Task 5: Pipeline wiring, one database build per run

**Files:**
- Modify: `tee-usage-scanner/internal/pipeline/run.go`
- Modify: `tee-usage-scanner/internal/pipeline/stage_events_test.go`

**Interfaces:**
- Produces: stages `repo_index` and `project_map` between `preprocess` and `architecture`
- Produces: `codedb.Manager` constructed once and passed to both `repoindex` and `newFactEngine`

- [ ] **Step 1: Extend the stage-coverage test** with the two new names in position.
- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Wire the stages**

`Engine` and `DatabaseProvider` are peer dependencies, not one wrapping the other — the engine runs queries, the provider owns the database's lifecycle:

```go
	eng := newFactEngine(exec, runID)
	db := codedb.New(eng, exec)
	// 01A / 01B
	repoindex.Run(stageCfg, db, eng)
	projectmap.Run(stageCfg)
	// the planner's fact layer takes the same provider value
	registry := NewFactRegistry(eng, db, ...)
```

Describing this as "pass the Manager to `newFactEngine`" would invite an implementer to hang the provider off the engine, and the single-build constraint would then hold only by accident.
- [ ] **Step 4: Verify the planner no longer builds a database** — no `codeql-database-create` event may carry `agent: planner-001`.
- [ ] **Step 5: Run everything.**
- [ ] **Step 6: Commit**

```bash
git commit -m "pipeline: build the program index once, before the planner"
```

---

## Task 6: Browsing actions

**Files:**
- Create: `tee-usage-scanner/internal/planner/actions/project_map.go`
- Test: `tee-usage-scanner/internal/planner/actions/project_map_test.go`
- Modify: `tee-usage-scanner/internal/planner/actions/registry_with_nav.go`
- Modify: `tee-usage-scanner/internal/planner/prompt.go`

**Interfaces:**
- Produces: `GetRepositoryCardHandler` (`get_repository_card`), `ListModulesHandler` (`list_modules`), `ListFunctionsHandler` (`list_functions`), `FindSymbolsHandler` (`find_symbols`), `GetFunctionCardHandler` (`get_function_card`), `GetCallersHandler` (`get_callers`)
- Produces: their `actionArgSchemas` entries

`get_repository_card` exists because Task 7's gate needs an observable event for the ORIENT state; without it `RepositoryCardRead` could never become true. `find_symbols` exists because the Planner knows names, not ids: it searches by name, receives candidates with their ids, and then asks for one.

- [ ] **Step 1: Write the failing tests**

Cover:
- every action's output is capped at `observationlimits.MaxBytes` and sets `ActionResult.Truncated` when it cuts
- `list_functions` returns a `next_cursor` and states `page N of M`
- `find_symbols` on an ambiguous name never picks one; it returns candidates with distinct ids, and when they do not fit the byte cap it pages and says how many matched in total ("all candidates" and "never over the cap" cannot both hold on a name with hundreds of matches)
- `get_function_card` on an unknown id fails with a refusal naming its scope — `not_found_in_indexed_repository`, plus the capability that was consulted
- `get_callers` states `callers_scope: direct_resolved_calls_only` and the run's unresolved-call count in the same output, so the model sees the limit next to the answer
- no handler declares its own byte cap; each uses `observationlimits.MaxBytes`
- with an unavailable index every handler says `unavailable`, distinct from an empty result

```go
// A refusal that does not name its scope is how "no caller found" becomes
// "no caller exists". ARCHITECTURE.md §7 fixes the vocabulary.
func TestGetFunctionCard_UnknownIDCarriesItsScope(t *testing.T) {
	res := GetFunctionCardHandler{}.Run(context.Background(), ActionRequest{
		RunDir: writeProbeIndex(t), Args: json.RawMessage(`{"symbol_id":"cpp:x.c:1:nope()"}`),
	})
	if res.OK {
		t.Fatal("an unknown id must not report success")
	}
	if !strings.Contains(res.Error, "not_found_in_indexed_repository") {
		t.Errorf("the refusal must use the §7 ladder: %s", res.Error)
	}
}
```

- [ ] **Step 2: Run to verify it fails**; **Step 3: implement**; **Step 4: verify**
- [ ] **Step 5: Register the handlers and advertise their arg schemas.**
- [ ] **Step 6: Run everything.**
- [ ] **Step 7: Commit**

```bash
git commit -m "planner: add the project-map browsing actions"
```

---

## Task 7: Observation references and one observation byte cap

`AuditLead.reason_fact_refs` has to point at something. Today `ActionResult` carries only `Name/OK/Output/Error/Truncated/DurationMs` (`internal/planner/actions/types.go:57`) — no identity — so there is nothing a lead could cite and nothing `open_audit_lead` could check. And a 32 KB page would not survive the trip anyway: `planner.go:439` truncates every observation to `truncate(result.Output, 4000)` with no marker, so a page built to a 32 KB budget reaches the model as 4 KB that looks complete.

Both are prerequisites for Task 8, and both are in the planner core rather than in a handler, which is why they are their own task.

**Files:**
- Create: `tee-usage-scanner/internal/planner/observation.go`
- Test: `tee-usage-scanner/internal/planner/observation_test.go`
- Modify: `tee-usage-scanner/internal/planner/planner.go`
- Modify: `tee-usage-scanner/internal/planner/actions/types.go`
- Modify: `tee-usage-scanner/internal/events/event.go`

**Interfaces:**
- Modifies: `artifacts.RoundObservation` (already exists, `internal/artifacts/types.go:548`) — add `Ref string`, `OutputBlob string`, `ActionIndex int`, `Phase string`. Do **not** declare a second observation type in `internal/planner`: `RoundRecord` is what the rounds log serialises, and a parallel type would be a shape that cannot be written to it.
- Produces: `func planner.MakeObservationRef(runID string, sampleIndex, round, actionIndex int, outputBlob string) string`
- Produces: `internal/observationlimits.MaxBytes` — one constant in a neutral package
- Produces: `events.TypePlannerObservationRecorded = "planner_observation_recorded"`
- Modifies: `planner.RunConfig` — add `SampleIndex int`

### Uniqueness: sample, not phase

Two different things are called a "pass" in this system today. `--samples N` makes `runL3Planner` drive the planner N times, each starting from round 1 (`pipeline/run.go`'s `for pass := 1; pass <= samples; pass++`). Separately this plan introduces Pass A (reconnaissance) and Pass B (investigation) *within* one such run.

They must not share a field. Two samples both reach round 3 action 1, so a ref built from `(round, actionIndex)` collides across samples, and a lead raised in sample 2 would cite sample 1's evidence.

```text
ObservationRef = run_id + sample_index + round + action_index + short(output_blob)
Phase          = "reconnaissance" | "investigation"   <- narrative only, never in the ref
AuditLead      carries sample_index
CoverageLedger one per run, with a by_sample breakdown — samples are unioned
               downstream, so a per-sample-file ledger would need re-aggregating
               by every consumer
```

### Event timing: a new event, not a retrofitted one

The ref is derived from the output blob, so it exists only after the action completes — and for executor-backed actions `tool_call_completed` has already been written by the executor by then (`planner.go` only emits it itself under `if !executorBacked`). There is no way to add a field to an event that is already on disk.

So the ref gets its own event, `planner_observation_recorded`, emitted by the planner after every action regardless of who emitted the tool events. It carries `observation_ref`, `action`, `ok`, `round`, `sample_index` and the output blob ref, which is also the join key back to the `tool_call_completed` that produced it. Nothing about the existing executor path changes.

### One byte cap, in a neutral package

The cap is used by `projectmap` (sizing pages), by the browsing actions (capping output) and by the planner core (excerpting observations). Putting it in `planner/actions` would make `projectmap` — a deterministic 01B stage — import the planner. It lives in `internal/observationlimits`, which imports nothing.

Task 4 and Task 6 refer to `observationlimits.MaxBytes`; neither declares its own `maxObservationBytes`.

- [ ] **Step 1: Write the failing test**

```go
package planner

import "testing"

// A lead that cites "the producer does not write key.version" has to point
// at the observation that showed it. Without an id there is nothing to point
// at, and reason_fact_refs degrades to free text shaped like a citation —
// which is BUG-003 §3.3 with extra steps.
func TestMakeObservationRef_IsStableAndDistinct(t *testing.T) {
	a := MakeObservationRef("run-1", 0, 3, 1, "sha256:aaa")
	again := MakeObservationRef("run-1", 0, 3, 1, "sha256:aaa")
	if a != again {
		t.Error("the same observation must produce the same ref")
	}
	for _, other := range []string{
		MakeObservationRef("run-1", 1, 3, 1, "sha256:aaa"), // different pass
		MakeObservationRef("run-1", 0, 4, 1, "sha256:aaa"), // different round
		MakeObservationRef("run-1", 0, 3, 2, "sha256:aaa"), // different action
		MakeObservationRef("run-1", 0, 3, 1, "sha256:bbb"), // different output
	} {
		if a == other {
			t.Errorf("distinct observations collided on %s", a)
		}
	}
}

// The page budget and the planner's excerpt must be the same number, or the
// page is sized for a limit that is not the one applied.
func TestObservationCap_HasExactlyOneDefinition(t *testing.T) {
	// grep is the assertion here: any package declaring its own byte cap for
	// observations has reintroduced the drift this constant exists to stop.
	if observationCap != observationlimits.MaxBytes {
		t.Errorf("planner caps at %d, the shared limit is %d", observationCap, observationlimits.MaxBytes)
	}
}

// A silent cut is the failure mode: the model reads 4 KB of a 32 KB page and
// has no way to know the rest exists.
func TestExcerpt_MarksWhatItCut(t *testing.T) {
	long := strings.Repeat("x", observationlimits.MaxBytes*2)
	got, truncated := excerpt(long)
	if !truncated {
		t.Fatal("an over-long output must report that it was cut")
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("the excerpt must say so in the text the model reads: %q", got[len(got)-120:])
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/planner/ -run "Observation|Excerpt" -v`
Expected: FAIL — `undefined: MakeObservationRef`

- [ ] **Step 3: Implement**

`MakeObservationRef` is `obs:<sample>:<round>:<index>:<short hash of runID+outputBlob>` — stable, short enough to appear in a prompt, and derived from the output blob so two identical actions in one round do not collide while a repeat of the same call resolves to the same evidence.

Delete the bare `truncate(result.Output, 4000)` at `planner.go:439`. Replace it with `excerpt()`, which cuts at `observationlimits.MaxBytes`, appends a marker naming the blob that holds the full body, and sets `Truncated`.

Every successful action's ref is (a) rendered into the observation the model sees, (b) written into `artifacts.RoundObservation.Ref` in the rounds log, (c) emitted as a `planner_observation_recorded` event, and (d) registered in the planner session's observation set for Task 8's validation.

- [ ] **Step 4: Run the tests to verify they pass**

- [ ] **Step 5: Fire drill** — restore the bare 4000-char truncate and confirm `TestObservationCap_IsSharedWithTheActions` FAILS. Restore.

- [ ] **Step 6: Commit**

```bash
git add tee-usage-scanner/internal/planner/ tee-usage-scanner/internal/events/
git commit -m "planner: give every observation a reference and one byte cap"
```

---

## Task 8: AuditLead, Coverage Ledger, and a project-first reconnaissance mode

This is the task that makes the Planner project-first. Everything before it only supplies the material.

**Files:**
- Create: `tee-usage-scanner/internal/artifacts/lead_types.go`
- Create: `tee-usage-scanner/internal/planner/recon.go`
- Create: `tee-usage-scanner/internal/planner/open_audit_lead.go`
- Modify: `tee-usage-scanner/internal/runfs/paths.go`
- Test: `tee-usage-scanner/internal/planner/recon_test.go`
- Test: `tee-usage-scanner/internal/planner/open_audit_lead_test.go`
- Modify: `tee-usage-scanner/internal/planner/planner.go`
- Modify: `tee-usage-scanner/internal/planner/prompt.go`
- Modify: `tee-usage-scanner/internal/pipeline/run.go`

**Interfaces:**
- Produces: `artifacts.AuditLead` per ARCHITECTURE.md §6.2, plus `ReasonFactRefs []string` binding each reason to a fact the Planner actually observed
- Produces: `artifacts.CoverageLedger` per ARCHITECTURE.md §6.5
- Produces: `planner.ReconState` with `Mode` ∈ {`indexed`, `tree_only`, `unavailable`}
- Produces: `runfs.AuditLeadsPath(runDir)` and `runfs.CoverageLedgerPath(runDir)` — new helpers beside the existing `runfs.RoundsLogPath`, resolving under `runfs.PlannerDir(runDir)`

**`open_audit_lead` is a control action in the planner core, not an `actions.Handler`.** It validates against the session's observation set from Task 7, and `actions.Handler.Run` receives only an `ActionRequest` — a handler would have to re-read artifacts from disk and guess what the planner saw. The planner dispatches it directly, the same way `done` is special-cased:

```go
// tryOpenAuditLead is dispatched by the planner loop, not by the registry.
// It needs the live ReconState and the observation set to check that the
// lead's symbols and reasons were actually seen this sample; a registry
// handler sees neither.
func tryOpenAuditLead(
	recon *ReconState,
	observations ObservationSet,
	payload OpenAuditLeadPayload,
) actions.ActionResult
```

It is advertised in the prompt's action list like any other action, so the model's interface is unchanged. Its tests live in `internal/planner/open_audit_lead_test.go`.

### Reconnaissance completion, per mode

The gate blocks **both** `done` and `open_audit_lead`. Blocking only `done` lets the model open one function, raise a lead, flip to Pass B and skip MAP entirely.

```text
indexed     RepositoryCard read
            AND distinct modules viewed  >= min(reconMinModules, modules_total)
            AND distinct symbols viewed  >= min(reconMinSymbols, functions_total)
            AND those symbols span       >= min(reconMinSpread, modules_total) modules
            AND at least one relation query succeeded — get_callers only

tree_only   list_dir on the root succeeded
            AND distinct files read      >= min(minTreeReads, files_total)

unavailable never satisfied by browsing; released only by the two escapes below
```

`reconMinModules`, `reconMinSymbols`, `reconMinSpread` and `minTreeReads` are declared as named constants with their rationale beside them, not inline numbers. Start at 5 / 15 / 3 / 5. They are floors against "concluded without reading", not coverage targets — OP-TEE has 11,301 indexed functions and no browse quota approaches coverage. The `min(...)` against the actual totals is what keeps a four-file fixture from being unsatisfiable.

The spread requirement is the one that resists gaming: fifteen functions from one module is not reconnaissance of a 34-module project, and without it the cheapest way to satisfy a count is to page through whatever the first `list_functions` returned.

`find_symbols` does not count as the relation query. It resolves a name to candidate ids — disambiguation, not a statement about how the code connects. Only `get_callers` qualifies today; add `get_callees` to the set when it exists.

Two escapes, both recorded:

- **final round** — the forced-`done` prompt at `planner.go:239` wins; the run records `recon_incomplete`
- **reconnaissance budget exhausted** — the gate stops blocking, the model is told to open a lead with what it has, and `ReconState` records `recon_budget_exhausted`

Neither escape may be silent: a run that finished gated must be distinguishable from one that finished.

- [ ] **Step 1: Write the failing recon tests**

```go
package planner

import (
	"strings"
	"testing"
)

// Counting calls lets the model open one function five times. The gate must
// count distinct things actually seen.
func TestReconState_CountsDistinctNotRepeats(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	for i := 0; i < 10; i++ {
		r.Observe("get_function_card", "cpp:a.c:1:f()", true)
	}
	if r.DistinctSymbolsViewed() != 1 {
		t.Errorf("opening one symbol ten times counted as %d", r.DistinctSymbolsViewed())
	}
}

// A failed action observed nothing. run-b had seven consecutive ripgrep
// failures; crediting those as browsing would satisfy a gate with no
// information behind it.
func TestReconState_IgnoresFailedActions(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.Observe("get_function_card", "cpp:a.c:1:f()", false)
	if r.DistinctSymbolsViewed() != 0 {
		t.Error("a failed action must not count as browsing")
	}
}

// With no index there is nothing to browse — but "nothing to browse" must
// not become "read nothing at all". The tree-only mode still requires real
// source reading.
func TestReconState_TreeOnlyStillRequiresReading(t *testing.T) {
	r := NewReconState(ReconModeTreeOnly)
	if r.Satisfied() {
		t.Fatal("tree_only must not be satisfied by default")
	}
	r.Observe("list_dir", ".", true)
	if r.Satisfied() {
		t.Error("a directory listing alone is not reconnaissance")
	}
	for i := 0; i < minTreeReads; i++ {
		r.Observe("read_file", fmt.Sprintf("core/f%d.c", i), true)
	}
	if !r.Satisfied() {
		t.Error("a listing plus real reads must satisfy tree_only")
	}
}

// The forced-done final round (planner.go:239) and the gate must not
// contradict each other: the model cannot be told both "you MUST call done"
// and "done is refused".
func TestReconState_FinalRoundOverridesTheGate(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	if !r.AllowDone(true) {
		t.Error("on the final round done must be allowed regardless of the gate")
	}
	if r.AllowDone(false) {
		t.Error("before the final round an unmet gate must still refuse done")
	}
	if r.TerminationReason(true) != terminationReconIncomplete {
		t.Error("a run that finished gated must be distinguishable from one that finished")
	}
}
```

- [ ] **Step 2: Run to verify it fails**; **Step 3: write `recon.go`**

`ReconState` holds sets, not counters; `Observe(action, key string, ok bool)` ignores `ok == false`; `Mode` is set at planner start from `repo_facts.capabilities`. `AllowDone(isFinalRound bool)` returns true when the gate is satisfied **or** it is the final round — the forced-`done` prompt at `planner.go:239` wins, and the run records `terminationReconIncomplete` so the two outcomes stay distinguishable.

- [ ] **Step 4: Write the failing `tryOpenAuditLead` tests**

```go
// A lead whose reasons cite nothing the planner looked at is a guess with a
// citation-shaped field. BUG-003 §3.3 is exactly that: an invariant anchored
// on a line nobody had read.
func TestOpenAuditLead_RejectsReasonsWithNoObservedFact(t *testing.T) {
	recon := NewReconState(ReconModeIndexed)
	res := tryOpenAuditLead(recon, ObservationSet{}, OpenAuditLeadPayload{
		SecurityQuestion: "does subkey_version reach pub_key.version?",
		TargetSymbolIDs:  []artifacts.SymbolID{"cpp:core/crypto/signed_hdr.c:262:shdr_load_pub_key()"},
		Reason:           []string{"producer does not write key.version"},
		ReasonFactRefs:   nil,
	})
	if res.OK {
		t.Fatal("a lead with no fact refs must be refused")
	}
	if !strings.Contains(res.Error, "reason_fact_refs") {
		t.Errorf("the refusal must name what is missing: %s", res.Error)
	}
}

func TestOpenAuditLead_RejectsUnobservedSymbols(t *testing.T) { /* symbol never browsed this pass */ }
func TestOpenAuditLead_WritesTheLeadAndFlipsToInvestigation(t *testing.T) { /* state=open, mode switches */ }
```

- [ ] **Step 5: Implement `tryOpenAuditLead`**

It validates that every `target_symbol_ids` entry and every `reason_fact_refs` entry was observed by a successful action **in this pass**, appends the lead to `runfs.AuditLeadsPath(runDir)` with `state: "open"`, and flips the Planner from reconnaissance to investigation. That flip is the only way Pass B opens.

- [ ] **Step 6: Cut every path by which the old invariants still steer the Planner**

The prompt is only half of it. Four separate channels carry the old Architecture/Invariant into the Planner today, and clearing the prompt while leaving the others would produce a run that *looks* project-first and whose evidence-gathering is still decided by the pre-planner invariants.

| Channel | Where | Change |
|---|---|---|
| System prompt sections | `prompt.go:95-107` renders `ARCHITECTURE MODEL` and `PROJECT INVARIANTS` | Pass A passes `PriorKnowledge{}`; both passes omit Architecture and the old ProjectInvariants |
| TWE catalog text | `PriorKnowledge.TWEText`, first section of the prompt | Pass A omits it; Pass B restores it |
| Obligations block | `BuildSystemPrompt`'s `obligationsBlock` | Pass A passes empty |
| **Fact-layer prefetch** | `prefetch.go:114` `prefetchFactLayer` runs CodeQL queries *chosen from the invariants*, and `run.go:558` feeds the refs to the Planner as `PrefetchedToolFactRefs`, which `planner.go:620` unions into **every** investigation's `tool_fact_refs` | Remove from the Planner's construction entirely |

The fourth is the one that survives a prompt-only fix. Those ToolFacts are not decoration: they are attached to every investigation the Planner emits, so a lead the model reached on its own still ships evidence that the old invariant selected. Delete `PrefetchedToolFactRefs` from the Planner's `RunConfig` and stop calling `prefetchFactLayer` on the Planner path. If the downstream review chain turns out to need those facts, they can be prefetched into `02_tool_facts/` for the *expert* stage — but they must not reach the Planner, and they must not appear in a Lead or a Case.

`BuildSystemPrompt` grows a `pass` parameter. Pass A's opening states that the job is to understand this project from its own code and to find relations the map cannot explain; the words "TWE-guided investigations" (`prompt.go:82`) are gone from it.

- [ ] **Step 6b: Refuse `twe_playbook_detail` in Pass A in code, not in prose**

A prompt instruction not to use an action is a request. The registry the Planner is given in Pass A does not contain `twe_playbook_detail`; a call to it returns `unknown action`. Pass B registers it.

Test it directly:

```go
// Pass A must be project-first by construction. An instruction the model can
// ignore is not a constraint — on run-b the planner's very first two actions
// were twe_playbook_detail calls, because the catalog sat at the top of its
// prompt.
func TestPassA_RefusesTWEPlaybookDetail(t *testing.T) {
	reg := ReconRegistry()
	if _, ok := reg.Lookup("twe_playbook_detail"); ok {
		t.Error("twe_playbook_detail must not be reachable during Pass A")
	}
	if _, ok := InvestigationRegistry().Lookup("twe_playbook_detail"); !ok {
		t.Error("Pass B must restore it")
	}
}
```

- [ ] **Step 7: Write the Coverage Ledger**

At planner end, write `runfs.CoverageLedgerPath(runDir)` with the ARCHITECTURE.md §6.5 fields. `unreviewed_clusters` lists modules with zero viewed capsules — recorded as a coverage gap, never as "nothing there".

- [ ] **Step 8: Separate the budgets**

A reconnaissance round counter distinct from the investigation counter, so browsing cannot consume the investigation budget. When the reconnaissance budget is exhausted the Planner is told to open a lead with what it has; the gate stops blocking and `ReconState` records `recon_budget_exhausted`.

- [ ] **Step 9: Run everything**

Run: `cd tee-usage-scanner && go test ./... && gofmt -l internal cmd && go vet ./...`

- [ ] **Step 10: Fire drills**

Each must FAIL when broken, then be restored: `Satisfied()` returning true unconditionally; `Observe` counting failed actions; `tryOpenAuditLead` skipping the fact-ref check; Pass A re-injecting `PriorKnowledge`.

- [ ] **Step 11: Commit**

```bash
git add tee-usage-scanner/internal/planner/ tee-usage-scanner/internal/artifacts/ tee-usage-scanner/internal/pipeline/
git commit -m "planner: project-first reconnaissance, audit leads and a coverage ledger"
```

---

## Acceptance

Run against the pinned revision:

```bash
cd tee-usage-scanner
./teecheck run https://github.com/OP-TEE/optee_os \
  --commit a9386bf987d95374a6f7f4c7bcf850115e0e1a4e \
  --run-id recon-001
```

**Index correctness**

- [ ] `repo_facts.v1.json` validates against `schema.RepoFactsV1`
- [ ] `capabilities` has a per-capability verdict; no field is the string `complete`
- [ ] `total_call_sites == resolved_call_sites + len(unresolved_call_sites)`
- [ ] the fixture test proves `UnresolvedCalls.ql` matches a function-pointer call (a real repo may legitimately have zero, so zero here is not a failure)
- [ ] no capsule carries a field name containing `risk`, `priority`, `candidate`, `suspicious`, `severity` or `twe`
- [ ] two same-named `static` functions appear as two symbols with distinct ids

**Project-first reconnaissance**

- [ ] the Pass A system prompt blob contains no TWE catalog text, no `ARCHITECTURE MODEL` section and no `PROJECT INVARIANTS` section
- [ ] `twe_playbook_detail` does not appear in any Pass A round, and is refused as `unknown action` if attempted
- [ ] every `AuditLead.reason_fact_refs` entry is an observation ref present in the rounds log with `ok: true`
- [ ] the coverage ledger exists, and `unreviewed_clusters` is populated rather than empty-by-omission
- [ ] no investigation's `tool_fact_refs` contains a ToolFact the Planner did not itself execute (the prefetch channel is closed)
- [ ] no run terminates with `recon_incomplete` — one that does is evidence that the reconnaissance budget is too small, and Task 8 Step 8's split needs revisiting with that run

**Observation discipline**

- [ ] every action result is ≤ `observationlimits.MaxBytes`, and any that cut sets `Truncated`; no observation in the rounds log was cut a second time without a marker
- [ ] every negative result in the artifacts carries a §7 ladder value; `grep -c '"not_found"' ` returns 0

**Not measured here**

Architecture `unknown` counts and invariant citation quality are deliberately absent. "Fewer unknowns is better" rewards a model for replacing an honest `unknown` with an unevidenced `inferred` — the exact behaviour BUG-003 exists to stop. Invariant citation quality belongs to Phase 3's `CaseInvariant` acceptance, where the invariant is bound to observed facts by construction.
