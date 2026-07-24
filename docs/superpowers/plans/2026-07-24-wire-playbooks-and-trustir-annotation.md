# Wire TWEPlaybooks + TrustIR Annotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the already-built TWE playbook context and TrustIR LLM annotation into production `runL3Planner`, so playbook context reaches CasePacks and unknown repos get LLM-annotated fact tables (known fixtures still win).

**Architecture:** Two independent wirings in `internal/pipeline/runL3Planner`, plus one new exported predicate in `trustirfacts`. A pipeline adapter maps `twecontext.Playbook → planner.TWEPlaybookSummary`; a pipeline decision helper annotates the fact table only when the repo has no hand-authored fixture.

**Tech Stack:** Go, `internal/{pipeline,trustirfacts,twecontext,planner,twe}`.

## Global Constraints

- **Known fixture takes priority**: `AnnotateFactTable`+`SetFactTable` run ONLY when the repo has no known deterministic fixture (`!HasKnownFactTable(repo)`). Known-fixture repos behave exactly as today.
- Annotation/catalog-load failures log and fall back safely — never hard-fail the pipeline.
- Do NOT change the planner loop, the fact-layer query semantics, the annotation prompt, or the factsource merge logic.
- `go build ./...`, `go vet ./...`, `go test ./...` green at the end (except the pre-existing `internal/collabrun` live-endpoint failures); benchmark unaffected.
- The pipeline package converts `twecontext.Playbook → planner.TWEPlaybookSummary` (planner must NOT gain a dependency on `twecontext`).

---

## Task 1: `trustirfacts.HasKnownFactTable` exported predicate

**Files:**
- Modify: `tee-usage-scanner/internal/trustirfacts/facttable.go`
- Test: `tee-usage-scanner/internal/trustirfacts/facttable_test.go` (add to existing, or create if absent)

**Interfaces:**
- Produces: `func HasKnownFactTable(repository string) bool`

- [ ] **Step 1: Write the failing test**

Look at the existing `knownFactTables` map (facttable.go ~line 149) to find a real key it contains (a normalized OP-TEE repo URL — reuse whatever key an existing `factTableFor`/known-table test already uses). Add:

```go
func TestHasKnownFactTable(t *testing.T) {
	// A repository WITH a hand-authored fixture reports true.
	// (Use the same repo string an existing known-table test uses — see knownFactTables.)
	known := <the repository string that keys an entry in knownFactTables>
	if !HasKnownFactTable(known) {
		t.Errorf("HasKnownFactTable(%q) = false, want true (it has a fixture)", known)
	}
	// A repository with no fixture reports false.
	if HasKnownFactTable("https://example.com/not/a/real/repo") {
		t.Errorf("HasKnownFactTable(unknown) = true, want false")
	}
	// Normalization: the same repo with trailing slash / case variance still hits.
	if !HasKnownFactTable(strings.ToUpper(known)) {
		t.Errorf("HasKnownFactTable should normalize repository like factTableFor does")
	}
}
```
(Add `"strings"` to the test imports if not present.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/trustirfacts/ -run TestHasKnownFactTable -v`
Expected: FAIL — `undefined: HasKnownFactTable`.

- [ ] **Step 3: Implement**

In `facttable.go`, next to `factTableFor`/`isLLMFactTable`:
```go
// HasKnownFactTable reports whether repository has a hand-authored
// deterministic fixture in knownFactTables, independent of any
// LLM-annotated table registered via SetFactTable. Callers use it to
// decide whether to run LLM annotation (known fixtures take priority).
func HasKnownFactTable(repository string) bool {
	_, ok := knownFactTables[normalizeRepo(repository)]
	return ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd tee-usage-scanner && go test ./internal/trustirfacts/ -run TestHasKnownFactTable -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/trustirfacts/facttable.go tee-usage-scanner/internal/trustirfacts/facttable_test.go
git commit -m "feat(trustirfacts): HasKnownFactTable predicate for known-priority annotation"
```

---

## Task 2: Pipeline annotation decision helper + wire into runL3Planner

**Files:**
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (add helper + call in `runL3Planner`)
- Test: `tee-usage-scanner/internal/pipeline/annotate_test.go` (create)

**Interfaces:**
- Consumes: `trustirfacts.HasKnownFactTable` (Task 1), `trustirfacts.AnnotateFactTable(ctx, client, twe.EnumRegistry, sourceRoot)`, `trustirfacts.SetFactTable(repo, table)`, `twe.LoadEnumRegistry(path)`.
- Produces: `func maybeAnnotateFactTable(ctx context.Context, client llm.Client, repository, sourceRoot, enumRegistryPath string) (attempted bool, err error)`

**Behavior:** if `HasKnownFactTable(repository)` → return `(false, nil)` (skip, known wins). Else load the enum registry; call `AnnotateFactTable`; on success + non-empty table call `SetFactTable(repository, table)`; return `(true, <err or nil>)`. All error paths return `(true/false, err)` for the caller to log — never panic.

- [ ] **Step 1: Write the failing test**

```go
package pipeline

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

// For a repo that HAS a known fixture, annotation must NOT be attempted:
// the LLM client is never called.
func TestMaybeAnnotate_KnownRepo_SkipsAnnotation(t *testing.T) {
	known := <the same repository string keying a knownFactTables entry (see Task 1)>
	fake := &llmtest.FakeClient{}
	attempted, err := maybeAnnotateFactTable(context.Background(), fake, known, t.TempDir(), "")
	if attempted {
		t.Errorf("attempted=true for a known-fixture repo, want false (known wins)")
	}
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("LLM was called %d times for a known repo; annotation must be skipped", len(fake.Calls))
	}
}

// For an unknown repo, annotation IS attempted (enum registry load will fail
// with an empty path, which is fine — we only assert the decision to attempt).
func TestMaybeAnnotate_UnknownRepo_AttemptsAnnotation(t *testing.T) {
	fake := &llmtest.FakeClient{}
	attempted, _ := maybeAnnotateFactTable(context.Background(), fake, "https://example.com/unknown/repo", t.TempDir(), "/nonexistent/enum.yml")
	if !attempted {
		t.Errorf("attempted=false for an unknown repo, want true (annotation should be tried)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ -run TestMaybeAnnotate -v`
Expected: FAIL — `undefined: maybeAnnotateFactTable`.

- [ ] **Step 3: Implement the helper**

Add to `run.go` (imports already include `context`, `fmt`, `trustirfacts`, `llm`; add `twe` import `github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe` if missing):
```go
// maybeAnnotateFactTable runs the TrustIR LLM annotation for repository
// ONLY when it has no hand-authored fixture (known fixtures take priority,
// §5). On success it registers the LLM table via SetFactTable so the fact
// layer prefers it. Returns whether annotation was attempted plus any error
// for the caller to log; it never hard-fails.
func maybeAnnotateFactTable(ctx context.Context, client llm.Client, repository, sourceRoot, enumRegistryPath string) (bool, error) {
	if trustirfacts.HasKnownFactTable(repository) {
		return false, nil
	}
	reg, err := twe.LoadEnumRegistry(enumRegistryPath)
	if err != nil {
		return true, fmt.Errorf("load enum registry: %w", err)
	}
	table, _, err := trustirfacts.AnnotateFactTable(ctx, client, reg, sourceRoot)
	if err != nil {
		return true, fmt.Errorf("annotate fact table: %w", err)
	}
	if table.Empty() {
		return true, nil
	}
	trustirfacts.SetFactTable(repository, table)
	return true, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ -run TestMaybeAnnotate -v`
Expected: PASS

- [ ] **Step 5: Wire the call into `runL3Planner`**

In `runL3Planner`, BEFORE the fact-layer registry is built (`registry := actions.NewDefaultRegistryWithFacts(eng, queryPackDir)`, ~line 302), add (the manifest is already loaded as `manifest`; `repoRoot` is the source root param):
```go
enumPath := filepath.Join(cfg.KnowledgeRoot, "twe", "definitions", "enum_registry.yml")
if _, aerr := maybeAnnotateFactTable(context.Background(), client, manifest.RepoURL, repoRoot, enumPath); aerr != nil {
	fmt.Printf("Warning: TrustIR fact-table annotation skipped: %v\n", aerr)
}
```

- [ ] **Step 6: Verify + commit**

Run: `cd tee-usage-scanner && go build ./internal/pipeline/ && go test ./internal/pipeline/ -run 'TestMaybeAnnotate|TestPipelineEndToEnd_FakeClient' -v`
Expected: PASS (the E2E test still passes — its repo has no known fixture so annotation is attempted against its fake client; the fake's `Default`/queued responses tolerate the extra call, and enum-registry load failing there just logs a warning).
If the E2E test breaks because the extra annotation LLM call consumes a queued response the later stages needed, adjust the E2E fake to use a `Default` (permissive) rather than a fixed short queue — note it in the report.

```bash
git add tee-usage-scanner/internal/pipeline/run.go tee-usage-scanner/internal/pipeline/annotate_test.go
git commit -m "feat(pipeline): annotate TrustIR fact table for repos without a known fixture"
```

---

## Task 3: Pipeline playbook adapter + wire TWEPlaybooks into RunConfig

**Files:**
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (add adapter + set `RunConfig.TWEPlaybooks`)
- Test: `tee-usage-scanner/internal/pipeline/playbooks_test.go` (create)

**Interfaces:**
- Consumes: `twecontext.Load(dir) (*twecontext.Catalog, error)`, `(*twecontext.Catalog).All() []twecontext.Playbook`, `planner.TWEPlaybookSummary`.
- Produces: `func playbookSummaries(cat *twecontext.Catalog) map[string]planner.TWEPlaybookSummary`

- [ ] **Step 1: Confirm the field sets, then write the failing test**

Read `planner.TWEPlaybookSummary` (planner.go ~line 103) and `twecontext.Playbook` (context.go ~line 130) to get their exact fields. `TWEPlaybookSummary` has at least `CommonDefenses []string` and `CommonFalsePositives []string`; map each `TWEPlaybookSummary` field from the same-named `Playbook` field, keyed by `Playbook.ID`. Write:

```go
package pipeline

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twecontext"
)

func TestPlaybookSummaries_MapsByTWEIDWithDefenses(t *testing.T) {
	cat := <construct a *twecontext.Catalog containing one Playbook with ID "TWE-STATE-001",
	         CommonDefenses ["rpmb counter"], CommonFalsePositives ["version field unused"]
	         — use twecontext's exported constructor/loader, or twecontext.Load against a
	         temp dir with a minimal playbook YAML; see twecontext tests for the pattern>
	got := playbookSummaries(cat)
	s, ok := got["TWE-STATE-001"]
	if !ok {
		t.Fatalf("no summary for TWE-STATE-001; got keys %v", got)
	}
	if len(s.CommonDefenses) != 1 || s.CommonDefenses[0] != "rpmb counter" {
		t.Errorf("CommonDefenses = %v, want [rpmb counter]", s.CommonDefenses)
	}
	if len(s.CommonFalsePositives) != 1 || s.CommonFalsePositives[0] != "version field unused" {
		t.Errorf("CommonFalsePositives = %v, want [version field unused]", s.CommonFalsePositives)
	}
}
```
(If constructing a `*twecontext.Catalog` directly is awkward because its fields are unexported, use `twecontext.Load(dir)` against a `t.TempDir()` seeded with one minimal playbook YAML file — copy the YAML shape from `knowledge/twe/playbooks/rollback.yml` and from an existing `twecontext` loader test.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ -run TestPlaybookSummaries -v`
Expected: FAIL — `undefined: playbookSummaries`.

- [ ] **Step 3: Implement the adapter**

Add to `run.go` (add the `twecontext` and `planner` imports if not present):
```go
// playbookSummaries adapts the TWE playbook catalog into the planner's
// dependency-free summary form, keyed by TWE ID, so the planner can attach
// common-defense / common-false-positive context to CasePacks without
// importing internal/twecontext.
func playbookSummaries(cat *twecontext.Catalog) map[string]planner.TWEPlaybookSummary {
	out := make(map[string]planner.TWEPlaybookSummary)
	if cat == nil {
		return out
	}
	for _, p := range cat.All() {
		out[p.ID] = planner.TWEPlaybookSummary{
			CommonDefenses:       p.CommonDefenses,
			CommonFalsePositives: p.CommonFalsePositives,
		}
	}
	return out
}
```
(If `planner.TWEPlaybookSummary` has MORE fields than `CommonDefenses`/`CommonFalsePositives`, map each of them from the same-named `twecontext.Playbook` field. Do not invent fields.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ -run TestPlaybookSummaries -v`
Expected: PASS

- [ ] **Step 5: Wire it into `runL3Planner`'s `RunConfig`**

Load the catalog once in `runL3Planner` (before the sample loop that builds `planner.RunConfig`, ~line 338). The playbook YAML lives under `<KnowledgeRoot>/twe/playbooks` (same tree the preprocessor compiles from):
```go
var playbooks map[string]planner.TWEPlaybookSummary
if cat, cerr := twecontext.Load(filepath.Join(cfg.KnowledgeRoot, "twe", "playbooks")); cerr == nil {
	playbooks = playbookSummaries(cat)
} else {
	fmt.Printf("Warning: TWE playbook catalog not loaded (%v); planner runs without playbook context\n", cerr)
}
```
Then add to the `planner.RunConfig{...}` literal:
```go
			TWEPlaybooks: playbooks,
```
(Verify `twecontext.Load`'s argument is the playbook directory — check its signature; if it expects a different root, use that. If the catalog fails to load, `playbooks` is nil and the planner tolerates a nil/empty map.)

- [ ] **Step 6: Verify + commit**

Run: `cd tee-usage-scanner && go build ./internal/pipeline/ && go test ./internal/pipeline/ -v`
Expected: PASS

```bash
git add tee-usage-scanner/internal/pipeline/run.go tee-usage-scanner/internal/pipeline/playbooks_test.go
git commit -m "feat(pipeline): pass TWE playbook context into the planner RunConfig"
```

---

## Task 4: Full-suite verification

- [ ] **Step 1: Build + vet + test**

Run: `cd tee-usage-scanner && go build ./... && go vet ./... && go test ./...`
Expected: all pass except the pre-existing `internal/collabrun` live-endpoint failures (confirm they are the same 2 and unrelated).

- [ ] **Step 2: Benchmark unaffected**

Run: `cd teecheck-benchmark && go build ./...`
Expected: success.

- [ ] **Step 3: Commit any tidy delta**

```bash
cd /root/pp_home/idea/TEECheck && git add -A && git commit -m "chore: verify full suite after playbook/annotation wiring" --allow-empty
```

---

## Self-Review Notes (coverage vs spec)

- Spec §4A (playbook adapter + wire) → Task 3.
- Spec §4B (HasKnownFactTable predicate) → Task 1; (known-priority annotation decision + wire) → Task 2.
- Spec §5 tests (predicate; known→skip / unknown→attempt via fake; adapter maps defenses) → Tasks 1/2/3 test steps.
- Spec §2 known-priority semantics → Task 2 helper (`!HasKnownFactTable` guard).
- Spec §7 acceptance 1-5 → Task 3 (playbooks), Task 1 (predicate), Task 2 (attempt decision + safe fallback), Task 4 (build/test/benchmark).
