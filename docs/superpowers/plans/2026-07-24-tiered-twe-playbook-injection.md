# TWE Playbook 分层注入 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render each TWE playbook at two tiers — a 250-token brief injected into every agent, and a 3000-token detail the planner pulls on demand — so playbooks can carry real expertise without multiplying every agent's prompt.

**Architecture:** One YAML stays the single source of truth; `internal/twecontext` grows two render functions and two ceilings. A new planner action `twe_playbook_detail` serves the full text, taking its catalog through a locally-declared interface so `internal/planner` keeps its deliberate non-dependency on `internal/twecontext`.

**Tech Stack:** Go, `internal/twecontext`, `internal/planner/actions`, `internal/pipeline`.

## Global Constraints

- Budgets: **brief ≤ 250 tokens**, **detail ≤ 3000 tokens**. Both **fail closed** (error, never truncate).
- Brief tier renders exactly: `[ID] Name | family=`, `Scenario`, `Look for`. Detail renders all 13 fields.
- Brief is checked in `Compile()`; detail is checked at load time (`Playbook.Validate()`), so an oversized playbook fails during preprocess, not when an agent pulls it.
- **No new YAML fields, no change to `schemas/twe-playbook.v1.json`, no change to `TWEKnowledgeManifest`.**
- `internal/planner` and `internal/planner/actions` must NOT import `internal/twecontext` — the action takes a locally-declared interface that `*twecontext.Catalog` satisfies structurally.
- Existing `knowledge/twe/playbooks/rollback.yml` must pass unchanged (measured: brief 213, detail 720).
- `go build ./...`, `go vet ./...`, `go test ./...` green (except the pre-existing `internal/collabrun` live-endpoint failures).

---

## Task 1: twecontext — two render tiers, two ceilings, Detail lookup

**Files:**
- Modify: `tee-usage-scanner/internal/twecontext/context.go`
- Test: `tee-usage-scanner/internal/twecontext/context_test.go` (add to existing)

**Interfaces:**
- Produces:
  - `func compileBriefBlock(p Playbook) string`
  - `func compileDetailBlock(p Playbook) string`
  - `func (c *Catalog) Detail(tweID string) (string, bool)`
  - consts `maxBriefContextTokens = 250`, `maxDetailContextTokens = 3000`

- [ ] **Step 1: Write the failing tests**

Add to `context_test.go` (check the existing file for its helper for building a Playbook / loading a temp catalog and reuse it; if none exists, build the literal inline as below):

```go
func testPlaybook() Playbook {
	return Playbook{
		SchemaVersion:        SchemaVersion,
		ID:                   "TWE-TEST-001",
		Name:                 "Test Weakness",
		Family:               twe.FamilyState,
		Scenario:             "A scenario sentence.",
		AttackerCapabilities: []string{"cap_one"},
		LookFor:              []string{"look_one"},
		InvestigationSteps:   []string{"step_one"},
		RequiredEvidence:     []string{"evidence_one"},
		CommonDefenses:       []string{"defense_one"},
		CommonFalsePositives: []string{"fp_one"},
		RelatedTWEs:          []string{"TWE-TEST-002"},
		TrustIRHints:         []string{"hint_one"},
	}
}

// The brief tier is what every agent carries, so it must contain only the
// two fields an agent needs to judge relevance — carrying the investigation
// method in the always-injected tier is the cost problem this change exists
// to fix.
func TestCompileBriefBlock_OnlyScenarioAndLookFor(t *testing.T) {
	got := compileBriefBlock(testPlaybook())
	for _, want := range []string{"TWE-TEST-001", "Test Weakness", "Scenario:", "Look for:"} {
		if !strings.Contains(got, want) {
			t.Errorf("brief missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"Investigate:", "Evidence required:", "Defenses:", "False positives:", "Attacker:", "Tool hints:"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("brief must not contain %q (detail-tier field):\n%s", unwanted, got)
		}
	}
}

func TestCompileDetailBlock_CarriesEveryField(t *testing.T) {
	got := compileDetailBlock(testPlaybook())
	for _, want := range []string{"Scenario:", "Attacker:", "Look for:", "Investigate:", "Evidence required:", "Defenses:", "False positives:", "Related:", "Tool hints:"} {
		if !strings.Contains(got, want) {
			t.Errorf("detail missing %q:\n%s", want, got)
		}
	}
}

// Fail closed, and name the offending playbook: a truncated playbook would
// silently give an agent half a method.
func TestCompile_FailsClosedOnOversizedBrief(t *testing.T) {
	p := testPlaybook()
	p.Scenario = strings.Repeat("word ", 400) // ~500 tokens, well over the 250 brief ceiling
	c := &Catalog{playbooks: []Playbook{p}}
	_, err := c.Compile()
	if err == nil {
		t.Fatal("expected Compile to fail closed on an oversized brief")
	}
	if !strings.Contains(err.Error(), "TWE-TEST-001") {
		t.Errorf("error must name the offending playbook, got: %v", err)
	}
}

func TestValidate_FailsClosedOnOversizedDetail(t *testing.T) {
	p := testPlaybook()
	p.InvestigationSteps = []string{strings.Repeat("step ", 3000)} // ~3750 tokens, over the 3000 detail ceiling
	err := p.Validate()
	if err == nil {
		t.Fatal("expected Validate to reject an oversized detail block")
	}
	if !strings.Contains(err.Error(), "TWE-TEST-001") {
		t.Errorf("error must name the offending playbook, got: %v", err)
	}
}

func TestCatalogDetail_HitAndMiss(t *testing.T) {
	c := &Catalog{playbooks: []Playbook{testPlaybook()}}
	text, ok := c.Detail("TWE-TEST-001")
	if !ok {
		t.Fatal("expected a hit for TWE-TEST-001")
	}
	if !strings.Contains(text, "Investigate:") {
		t.Errorf("Detail must return the full block, got:\n%s", text)
	}
	if _, ok := c.Detail("TWE-NOPE-999"); ok {
		t.Error("expected a miss for an unknown TWE id")
	}
}
```
(Ensure the test file imports `strings` and the `twe` package. Check what `twe.Family` constant exists for "State" — read `internal/twe`'s Family definitions and use the real constant name; if families are plain strings, use `twe.Family("State")`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/twecontext/ -run 'TestCompileBrief|TestCompileDetail|TestCompile_FailsClosed|TestValidate_FailsClosed|TestCatalogDetail' -v`
Expected: FAIL — `undefined: compileBriefBlock`, `undefined: compileDetailBlock`, `undefined: maxBriefContextTokens`, `Detail` undefined.

- [ ] **Step 3: Implement**

In `context.go`:

**(a)** Replace the single ceiling constant and its doc comment (currently `maxPlaybookContextTokens = 900` around line 31-46) with two:
```go
// maxBriefContextTokens bounds the tier that is injected into EVERY agent
// (Planner, Architecture, Invariant, Expert, Challenger, Verifier, Arbiter),
// for every playbook, on every LLM call. That multiplier is why this tier
// carries only what an agent needs to judge relevance — scenario and
// look_for. Measured: rollback.yml's brief is ~213 tokens.
const maxBriefContextTokens = 250

// maxDetailContextTokens bounds the tier the Planner pulls on demand via the
// twe_playbook_detail action. It is paid for only when an agent asks for a
// specific TWE, so it can afford the real investigation method: concrete API
// names, code patterns, and the reasoning behind each defense. Measured:
// rollback.yml's detail is ~720 tokens, leaving room to grow ~4x.
const maxDetailContextTokens = 3000
```

**(b)** Rename `compilePlaybookBlock` → `compileDetailBlock` (body unchanged — it already renders all 13 fields), and add the brief renderer next to it:
```go
// compileBriefBlock renders the always-injected tier: enough for an agent to
// decide whether this weakness family is relevant to the code in front of it,
// and nothing more. The full method lives in compileDetailBlock.
func compileBriefBlock(p Playbook) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n[%s] %s | family=%s\n", p.ID, p.Name, p.Family)
	writeField(&b, "Scenario", []string{p.Scenario})
	writeField(&b, "Look for", p.LookFor)
	return b.String()
}
```

**(c)** In `Compile()`, switch to the brief renderer and the brief ceiling:
```go
		block := compileBriefBlock(p)
		if tokens := estimateTokens(block); tokens > maxBriefContextTokens {
			return Compiled{}, fmt.Errorf(
				"%s: brief context is ~%d tokens (%d chars), which exceeds the %d-token compile-time ceiling; shrink the playbook's scenario or look_for — Compile must fail closed here, not truncate",
				p.ID, tokens, len(block), maxBriefContextTokens,
			)
		}
```

**(d)** Update `contextHeader` so an agent knows the brief is not the whole story:
```go
const contextHeader = "TWE PRIOR KNOWLEDGE (complete catalog, brief tier; apply every relevant playbook, do not treat it as a finding. The full investigation method for any TWE can be requested by its id.)\n"
```

**(e)** At the END of `Playbook.Validate()` (just before its final `return nil`), enforce the detail ceiling at load time:
```go
	if tokens := estimateTokens(compileDetailBlock(p)); tokens > maxDetailContextTokens {
		return fmt.Errorf(
			"%s: detail context is ~%d tokens, which exceeds the %d-token ceiling; shrink the playbook — this is checked at load so an oversized playbook fails during preprocess, not when an agent pulls it",
			p.ID, tokens, maxDetailContextTokens,
		)
	}
```

**(f)** Add the lookup API next to `All()`:
```go
// Detail returns the full rendering of one playbook. ok is false when no
// playbook carries that TWE id — callers surface that as an explicit miss
// rather than an empty result, so an agent never reads "no text" as "no
// weakness".
func (c *Catalog) Detail(tweID string) (string, bool) {
	for _, p := range c.playbooks {
		if p.ID == tweID {
			return compileDetailBlock(p), true
		}
	}
	return "", false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/twecontext/ -v`
Expected: PASS, including any pre-existing tests. If a pre-existing test asserted the old 900 constant name or that `Compile` output contains `Investigate:`, update it to the new tiering (the brief legitimately no longer carries those fields) — do not weaken it to assert nothing.

- [ ] **Step 5: Verify the shipped playbook still loads and compiles**

Run: `cd tee-usage-scanner && go test ./internal/preprocessor/ && go test ./internal/pipeline/ -run TestPipelineEndToEnd_FakeClient`
Expected: PASS — `rollback.yml` is measured at brief 213 / detail 720, both within budget.

- [ ] **Step 6: Commit**

```bash
git add tee-usage-scanner/internal/twecontext/
git commit -m "feat(twecontext): two-tier playbook rendering with separate ceilings"
```

---

## Task 2: `twe_playbook_detail` planner action

**Files:**
- Create: `tee-usage-scanner/internal/planner/actions/twe_playbook_detail.go`
- Test: `tee-usage-scanner/internal/planner/actions/twe_playbook_detail_test.go`

**Interfaces:**
- Consumes: `Catalog.Detail(tweID string) (string, bool)` (Task 1) — but **via a locally-declared interface**, not by importing twecontext.
- Produces:
  - `type PlaybookDetailSource interface { Detail(tweID string) (string, bool) }`
  - `type TWEPlaybookDetailHandler struct { Source PlaybookDetailSource }` implementing `Handler`

- [ ] **Step 1: Write the failing test**

```go
package actions

import (
	"context"
	"strings"
	"testing"
)

type fakeDetailSource struct {
	byID  map[string]string
	calls []string
}

func (f *fakeDetailSource) Detail(tweID string) (string, bool) {
	f.calls = append(f.calls, tweID)
	text, ok := f.byID[tweID]
	return text, ok
}

func TestTWEPlaybookDetail_ReturnsFullText(t *testing.T) {
	src := &fakeDetailSource{byID: map[string]string{
		"TWE-STATE-001": "[TWE-STATE-001] Trusted State Rollback\nInvestigate: step_one\nFalse positives: fp_one\n",
	}}
	h := &TWEPlaybookDetailHandler{Source: src}
	res := h.Run(context.Background(), ActionRequest{Args: []byte(`{"twe_id":"TWE-STATE-001"}`)})
	if !res.OK {
		t.Fatalf("expected OK, got error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "False positives:") {
		t.Errorf("expected the detail-tier text, got:\n%s", res.Output)
	}
	if len(src.calls) != 1 || src.calls[0] != "TWE-STATE-001" {
		t.Errorf("expected one lookup for TWE-STATE-001, got %v", src.calls)
	}
}

// An unknown id must be an explicit error, never an empty success — an agent
// must not read "no text" as "this weakness does not apply".
func TestTWEPlaybookDetail_UnknownIDIsAnError(t *testing.T) {
	h := &TWEPlaybookDetailHandler{Source: &fakeDetailSource{byID: map[string]string{}}}
	res := h.Run(context.Background(), ActionRequest{Args: []byte(`{"twe_id":"TWE-NOPE-999"}`)})
	if res.OK {
		t.Fatal("expected OK=false for an unknown TWE id")
	}
	if res.Error == "" {
		t.Error("expected a non-empty Error explaining the miss")
	}
}

func TestTWEPlaybookDetail_RejectsBadArgs(t *testing.T) {
	h := &TWEPlaybookDetailHandler{Source: &fakeDetailSource{byID: map[string]string{}}}
	if res := h.Run(context.Background(), ActionRequest{Args: []byte(`{}`)}); res.OK {
		t.Error("expected OK=false when twe_id is missing")
	}
	if res := h.Run(context.Background(), ActionRequest{Args: []byte(`not json`)}); res.OK {
		t.Error("expected OK=false for malformed args")
	}
}

// The catalog can legitimately be absent (a knowledge root with no playbook
// directory); the action must fail per call rather than panic.
func TestTWEPlaybookDetail_NilSourceFailsClosed(t *testing.T) {
	h := &TWEPlaybookDetailHandler{}
	res := h.Run(context.Background(), ActionRequest{Args: []byte(`{"twe_id":"TWE-STATE-001"}`)})
	if res.OK || res.Error == "" {
		t.Error("expected a per-call failure when no catalog is loaded")
	}
}

func TestTWEPlaybookDetail_Name(t *testing.T) {
	if got := (&TWEPlaybookDetailHandler{}).Name(); got != "twe_playbook_detail" {
		t.Errorf("Name() = %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestTWEPlaybookDetail -v`
Expected: FAIL — `undefined: TWEPlaybookDetailHandler`.

- [ ] **Step 3: Implement**

Create `twe_playbook_detail.go`:
```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// PlaybookDetailSource supplies the full text of one TWE playbook.
// *twecontext.Catalog satisfies it structurally, so this package — and
// internal/planner with it — keeps its deliberate non-dependency on
// internal/twecontext (see planner.TWEPlaybookSummary's doc comment).
type PlaybookDetailSource interface {
	Detail(tweID string) (string, bool)
}

type twePlaybookDetailArgs struct {
	TWEID string `json:"twe_id"`
}

// TWEPlaybookDetailHandler serves the detail tier of the TWE prior knowledge.
// Every agent already carries the brief tier (id, name, family, scenario,
// look_for); this action returns the full investigation method for one TWE so
// the deep content is paid for only when the planner decides a family is
// relevant.
type TWEPlaybookDetailHandler struct {
	Source PlaybookDetailSource
}

func (h *TWEPlaybookDetailHandler) Name() string { return "twe_playbook_detail" }

func (h *TWEPlaybookDetailHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args twePlaybookDetailArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("twe_playbook_detail", fmt.Sprintf("invalid args: %v", err))
	}
	id := strings.TrimSpace(args.TWEID)
	if id == "" {
		return fail("twe_playbook_detail", "twe_id is required")
	}
	if h.Source == nil {
		return fail("twe_playbook_detail", "no TWE playbook catalog is loaded for this run")
	}
	text, ok := h.Source.Detail(id)
	if !ok {
		return fail("twe_playbook_detail", fmt.Sprintf("no playbook for %s — check the id against the brief catalog in your system prompt", id))
	}
	return ActionResult{Name: "twe_playbook_detail", OK: true, Output: text}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestTWEPlaybookDetail -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/planner/actions/twe_playbook_detail.go tee-usage-scanner/internal/planner/actions/twe_playbook_detail_test.go
git commit -m "feat(planner): twe_playbook_detail action serving the detail tier"
```

---

## Task 3: Wire the action into the registry, pipeline, and prompt

**Files:**
- Modify: `tee-usage-scanner/internal/planner/actions/registry_with_facts.go`
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (`runL3Planner`)
- Modify: `tee-usage-scanner/internal/planner/prompt.go`
- Test: `tee-usage-scanner/internal/planner/actions/registry_test.go`, `tee-usage-scanner/internal/planner/prompt_test.go`

**Interfaces:**
- Consumes: `TWEPlaybookDetailHandler` + `PlaybookDetailSource` (Task 2); `twecontext.Load(dir) (*Catalog, error)` and `Catalog.Detail` (Task 1).
- Produces: `func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, queryPackDir string, playbooks PlaybookDetailSource) *Registry` — NOTE the new third parameter.

- [ ] **Step 1: Write the failing tests**

In `registry_test.go`:
```go
func TestFactsRegistry_RegistersPlaybookDetail(t *testing.T) {
	r := NewDefaultRegistryWithFacts(nil, "", nil)
	found := false
	for _, n := range r.Names() {
		if n == "twe_playbook_detail" {
			found = true
		}
	}
	if !found {
		t.Errorf("twe_playbook_detail must be registered, got %v", r.Names())
	}
}
```
In `prompt_test.go`:
```go
func TestBuildSystemPrompt_DocumentsPlaybookDetailAction(t *testing.T) {
	out := BuildSystemPrompt([]string{"ripgrep", "twe_playbook_detail", "done"}, "", PriorKnowledge{})
	if !strings.Contains(out, "twe_playbook_detail") {
		t.Error("system prompt must document the twe_playbook_detail action")
	}
	if !strings.Contains(out, "twe_id") {
		t.Error("system prompt must document the twe_id argument")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/planner/actions/ -run TestFactsRegistry_RegistersPlaybookDetail -v && go test ./internal/planner/ -run TestBuildSystemPrompt_DocumentsPlaybookDetailAction -v`
Expected: FAIL — wrong argument count for `NewDefaultRegistryWithFacts`; prompt lacks the action schema.

- [ ] **Step 3: Implement**

**(a)** `registry_with_facts.go` — add the parameter and register the handler:
```go
package actions

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"

// NewDefaultRegistryWithFacts extends NewDefaultRegistryWithNav with the
// fact_layer_query action (the Planner's entry point into the structured
// CodeQL/TrustIR fact layer) and twe_playbook_detail (the on-demand detail
// tier of the TWE prior knowledge).
//
// eng may be nil (facts off) and playbooks may be nil (a knowledge root with
// no playbook directory); both handlers then fail closed per call rather than
// at construction.
func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, queryPackDir string, playbooks PlaybookDetailSource) *Registry {
	r := NewDefaultRegistryWithNav()
	r.Register(&FactLayerQueryHandler{Engine: eng, QueryPackDir: queryPackDir})
	r.Register(&TWEPlaybookDetailHandler{Source: playbooks})
	return r
}
```

**(b)** `pipeline/run.go` in `runL3Planner` — load the catalog once and pass it. Add the `twecontext` import. Place this immediately before the `registry := ...` line (currently around line 302):
```go
	// The playbook catalog backs the twe_playbook_detail action. A knowledge
	// root without a playbook directory is tolerated (preprocess applies the
	// same policy): the action then fails per call instead of the run failing.
	var playbooks actions.PlaybookDetailSource
	if cat, cerr := twecontext.Load(filepath.Join(cfg.KnowledgeRoot, "twe", "playbooks")); cerr == nil {
		playbooks = cat
	} else {
		fmt.Printf("Warning: TWE playbook catalog not loaded (%v); twe_playbook_detail will report no catalog\n", cerr)
	}
	registry := actions.NewDefaultRegistryWithFacts(eng, queryPackDir, playbooks)
```
NOTE: a `*twecontext.Catalog` is assigned to an `actions.PlaybookDetailSource` here — that works because Go interfaces are structural. Assign it to the interface-typed variable (as above) rather than a concrete-typed one, so a nil catalog stays a nil interface.

**(c)** `planner/prompt.go` — document the action. In the `actionArgSchemas` map add:
```go
	"twe_playbook_detail": `{"twe_id": string (e.g. "TWE-STATE-001")} — returns the FULL investigation method for one TWE: attacker capabilities, investigation steps, required evidence, common defenses, and common false positives. Your system prompt carries only the brief tier; pull the detail for any TWE you are actually investigating`,
```
And add a step to the APPROACH block, after the invariant/TWE starting step:
```go
	b.WriteString("  2. When a TWE from the prior knowledge looks relevant to this code, call twe_playbook_detail with its id to get the full investigation method before you start searching.\n")
```
(Renumber the following APPROACH steps so the list stays sequential.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./... && go test ./internal/planner/... ./internal/pipeline/`
Expected: PASS. The de-anchoring test `TestBuildSystemPrompt_Deanchored` must still pass — the new text introduces no banned substring (`sink_catalog_lookup`, `Cargo`, `*.rs`); if it fails, fix the wording rather than the test.

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/planner/ tee-usage-scanner/internal/pipeline/run.go
git commit -m "feat(planner): wire twe_playbook_detail into registry, pipeline, and prompt"
```

---

## Task 4: Full-suite verification

- [ ] **Step 1: Build, vet, full test suite**

Run: `cd tee-usage-scanner && go build ./... && go vet ./... && go test ./...`
Expected: all packages pass except the pre-existing `internal/collabrun` live-endpoint failures (confirm they are the same ones and unrelated).

- [ ] **Step 2: Confirm no stale reference to the removed constant**

Run: `cd tee-usage-scanner && grep -rn "maxPlaybookContextTokens\|compilePlaybookBlock" --include="*.go" .`
Expected: no output (both were renamed in Task 1).

- [ ] **Step 3: Confirm the layering constraint holds**

Run: `cd tee-usage-scanner && grep -rn "twecontext" --include="*.go" internal/planner/`
Expected: no output — `internal/planner` and its `actions` subpackage must not import `internal/twecontext`.

- [ ] **Step 4: Benchmark unaffected**

Run: `cd teecheck-benchmark && go build ./...`
Expected: success.

- [ ] **Step 5: Commit**

```bash
cd /root/pp_home/idea/TEECheck && git add -A
git commit -m "chore: verify full suite after tiered playbook injection" --allow-empty
```

---

## Self-Review Notes (coverage vs spec)

- Spec §4.1 two tiers + budgets (250/3000) → Task 1 (constants, two renderers, Compile switch).
- Spec §4.2 `Detail()` API + fail-closed placement (brief in Compile, detail in Validate) → Task 1 steps (e)(f).
- Spec §4.2 new action + `Handler` conformance + fail-per-call → Task 2.
- Spec §4.2 registry/prompt wiring → Task 3.
- Spec §4.3 reproducibility (detail pulls recorded via the existing action event path; manifest unchanged) → no code needed: the action goes through `Registry.Run`, which the planner already event-records; Task 4 Step 2/3 guard that nothing else changed. Manifest is untouched by construction (Task 1 leaves `Compiled.Manifest` assembly as-is).
- Spec §5 migration: none required — Task 1 Step 5 verifies `rollback.yml` still loads and compiles.
- Spec §7 non-goals honored: no YAML/schema/manifest changes in any task; no push mechanism for downstream agents.
- Spec §8 acceptance 1-6 → Task 1 (1,2,5), Task 2 (3), Task 3 (3), Task 4 (6) — acceptance 4 (events) covered by the existing planner event path, verified by Task 3's build/test of the planner package.
