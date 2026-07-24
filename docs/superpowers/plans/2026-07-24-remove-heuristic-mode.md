# Remove Heuristic Mode (LLM-only via injected client) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete every agent's heuristic branch and the Mode/sub-mode config + `-mode` CLI, leaving a single LLM code path; agents receive an injected `llm.Client` (explicit DI); tests swap in a fake client.

**Architecture:** Each agent entry point gains an `llm.Client` parameter; `llm.NewClient(cfg)` moves out of agents up to the orchestration layer (`pipeline` + `cmd/teecheck` subcommands). Heuristic branches (`if EqualFold(cfg.<X>Mode,"llm"){...}else{heuristic}`) collapse to the LLM path; `Build<X>Heuristic`/`build<X>Heuristic` helpers are deleted. Tests inject a shared `llmtest.FakeClient`.

**Tech Stack:** Go, `internal/{expert,challenger,verifier,arbiter,architecture,invariants,report,feedback,pipeline,config,llm}`, `cmd/teecheck`.

## Global Constraints

- `llm.GenerateResponse` fields are `Text string`, `Raw string`, `Usage llm.Usage` (NOT `Content`). The fake returns `GenerateResponse{Text: canned, Raw: canned}`.
- `llm.NewClient(cfg)` provider selection is NOT touched; v1 stays GLM-only. Multi-provider is preserved automatically because agents take the `llm.Client` interface.
- Deletions are real, not feature-flagged.
- The pipeline `Mode=="llm"` gate is KEPT solely as the L3-Planner-vs-legacy-scanner selector (unrelated to heuristic). Agent stages run in BOTH branches and take the injected client in both.
- The end-to-end pipeline smoke test runs with `Mode="llm"` + an injected fake client (tests the real L3 path); the legacy-scanner branch is kept compiling but gets no dedicated test.
- A fake client lives ONLY in `*_test.go` / a test-helper package — never in a production binary.
- `go build ./...`, `go vet ./...`, `go test ./...` must be green at the end; teecheck-benchmark unaffected.
- Migrated tests must keep asserting real behavior (given a canned LLM answer, the code produces the correct artifact) — never weakened to assert nothing.

---

## Task 1: Shared fake LLM client helper

**Files:**
- Create: `tee-usage-scanner/internal/llm/llmtest/fake.go`
- Test: `tee-usage-scanner/internal/llm/llmtest/fake_test.go`

**Interfaces:**
- Produces: `llmtest.FakeClient` implementing `llm.Client`:
  - fields `Responses []string`, `Default string`, `Err error`, `Calls []llm.GenerateRequest`
  - `func (f *FakeClient) Generate(ctx, req) (llm.GenerateResponse, error)`

- [ ] **Step 1: Write the failing test**

```go
package llmtest

import (
	"context"
	"errors"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func TestFakeClient_ReturnsQueuedThenDefault(t *testing.T) {
	f := &FakeClient{Responses: []string{"first", "second"}, Default: "fallback"}
	got1, _ := f.Generate(context.Background(), llm.GenerateRequest{})
	got2, _ := f.Generate(context.Background(), llm.GenerateRequest{})
	got3, _ := f.Generate(context.Background(), llm.GenerateRequest{})
	if got1.Text != "first" || got2.Text != "second" || got3.Text != "fallback" {
		t.Fatalf("got %q,%q,%q", got1.Text, got2.Text, got3.Text)
	}
	if got1.Raw != "first" {
		t.Errorf("Raw should mirror Text, got %q", got1.Raw)
	}
	if len(f.Calls) != 3 {
		t.Errorf("expected 3 recorded calls, got %d", len(f.Calls))
	}
}

func TestFakeClient_ReturnsErr(t *testing.T) {
	sentinel := errors.New("boom")
	f := &FakeClient{Err: sentinel}
	if _, err := f.Generate(context.Background(), llm.GenerateRequest{}); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/llm/llmtest/ -v`
Expected: FAIL — `undefined: FakeClient`.

- [ ] **Step 3: Write the fake**

```go
// Package llmtest provides test doubles for internal/llm. It is imported
// only from *_test.go files and never linked into a production binary.
package llmtest

import (
	"context"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// FakeClient is a deterministic llm.Client for tests. It returns the queued
// Responses in order (as GenerateResponse.Text and .Raw); once exhausted it
// returns Default. If Err is set, Generate returns it. Every request is
// recorded in Calls for assertions.
type FakeClient struct {
	Responses []string
	Default   string
	Err       error
	Calls     []llm.GenerateRequest
	idx       int
}

func (f *FakeClient) Generate(ctx context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	f.Calls = append(f.Calls, req)
	if f.Err != nil {
		return llm.GenerateResponse{}, f.Err
	}
	content := f.Default
	if f.idx < len(f.Responses) {
		content = f.Responses[f.idx]
		f.idx++
	}
	return llm.GenerateResponse{Text: content, Raw: content}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd tee-usage-scanner && go test ./internal/llm/llmtest/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/llm/llmtest/
git commit -m "test(llm): shared FakeClient test double"
```

---

## Task 2: Architecture — drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/architecture/build.go` (delete `Build` dispatch + `BuildHeuristic`)
- Modify: `tee-usage-scanner/internal/architecture/run.go` (Run signature + client)
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (introduce shared `client`, pass to architecture.Run)
- Test: `tee-usage-scanner/internal/architecture/run_test.go`, `build_test.go`

**Interfaces:**
- Consumes: `llmtest.FakeClient` (Task 1).
- Produces: `architecture.Run(cfg config.Config, client llm.Client) error`; `architecture.BuildLLM(ctx, client, in, temp)` remains (now the only build path).

- [ ] **Step 1: Update tests first (they drive the new shape)**

In `build_test.go`: delete any test of `BuildHeuristic`. Any test calling `Build(ctx, client, "heuristic", ...)` or `Build(ctx, nil, "llm", ...)` → call `BuildLLM(ctx, fake, in, temp)` with `fake := &llmtest.FakeClient{Default: <a valid architecture-model JSON string the existing test already used, or Responses:[...]>}`.
In `run_test.go`: replace `cfg := config.Config{..., Mode: "heuristic"}; architecture.Run(cfg)` with `architecture.Run(cfg, &llmtest.FakeClient{Responses: []string{<valid arch JSON>}})`. Keep assertions on the produced `ArchitectureModel`/dossier.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/architecture/ -v`
Expected: FAIL to compile — `Run` takes 1 arg / `BuildHeuristic` undefined etc.

- [ ] **Step 3: Apply production edits**

`build.go`:
- Delete `func Build(ctx, client, mode, in, temp)` (the mode dispatcher) and `func BuildHeuristic(in Input) artifacts.ArchitectureModel`.
- Keep `func BuildLLM(ctx context.Context, client llm.Client, in Input, temperature float64) (artifacts.ArchitectureModel, error)` unchanged.

`run.go`:
- Change signature to `func Run(cfg config.Config, client llm.Client) error`.
- Delete the block:
  ```go
  var client llm.Client
  if strings.EqualFold(cfg.Mode, "llm") { client = llm.NewClient(cfg) }
  ```
- Change `model, err := Build(context.Background(), client, cfg.Mode, in, cfg.LLMTemp)` → `model, err := BuildLLM(context.Background(), client, in, cfg.LLMTemp)`.
- Remove the now-unused `strings` / `llm` imports only if they become unused (they likely stay via other refs — check).

`pipeline/run.go`: immediately before the `architecture.Run` call (currently line ~112, after `preprocessor.Run`), introduce the shared client and pass it:
```go
client := llm.NewClient(cfg)
if err := architecture.Run(stageCfg, client); err != nil {
    return runDir, fmt.Errorf("architecture: %w", err)
}
```
(Add the `llm` import to pipeline/run.go if not present. This `client` variable will be reused by the invariants/expert/… calls in later tasks.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/architecture/ ./internal/pipeline/ && go test ./internal/architecture/ -v`
Expected: PASS. (Pipeline package may not fully build yet if a later stage still references removed config — but architecture + pipeline compile against this change; if pipeline fails only due to a not-yet-migrated stage, that is expected and handled in that stage's task. If so, note it and proceed — the architecture package tests are the gate here.)

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/architecture/ tee-usage-scanner/internal/pipeline/run.go
git commit -m "refactor(architecture): drop heuristic build, inject llm.Client"
```

---

## Task 3: Invariants — drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/invariants/build.go` (delete `Build` dispatch + `BuildHeuristic`)
- Modify: `tee-usage-scanner/internal/invariants/run.go`
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (pass the shared `client` to invariants.Run)
- Test: `tee-usage-scanner/internal/invariants/build_test.go`, `run_test.go`

**Interfaces:**
- Produces: `invariants.Run(cfg config.Config, client llm.Client) error`; `invariants.BuildLLM` remains the only build path.

- [ ] **Step 1: Update tests first**

`build_test.go`: delete `BuildHeuristic` tests; convert `Build(ctx, client, "heuristic"/"llm", ...)` calls to `BuildLLM(ctx, &llmtest.FakeClient{Responses: []string{<valid invariants JSON array the test needs>}}, in, temp)`.
`run_test.go`: the current `TestRun_HeuristicEndToEnd` (uses `Mode: "heuristic"` and asserts `len(out.Invariants)==0`) — replace with a fake-client run: `invariants.Run(cfg, &llmtest.FakeClient{Responses: []string{<valid invariants JSON>}})`, then read the persisted `ProjectInvariants` wrapper and assert the invariants the fake produced. Keep the schema-validation test (`TestSchemaValidation_RejectsEmptyStatement`) as-is (it tests `Validate`, not mode).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/invariants/ -v`
Expected: FAIL to compile.

- [ ] **Step 3: Apply production edits**

`build.go`: delete `func Build(ctx, client, mode, in, temp)` and `func BuildHeuristic(in Input) []artifacts.ProjectInvariant`; keep `BuildLLM`.
`run.go`: `func Run(cfg config.Config, client llm.Client) error`; delete the `if EqualFold(cfg.Mode,"llm"){client=NewClient}` block; change the `Build(...)` call to `BuildLLM(context.Background(), client, in, cfg.LLMTemp)`.
`pipeline/run.go`: `if err := invariants.Run(stageCfg, client); err != nil { ... }` (reuse the `client` var from Task 2).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/invariants/ && go test ./internal/invariants/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/invariants/ tee-usage-scanner/internal/pipeline/run.go
git commit -m "refactor(invariants): drop heuristic build, inject llm.Client"
```

---

## Task 4: Expert — drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/expert/run.go`
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (pass `client` to expert.RunWithEvents)
- Modify: `tee-usage-scanner/cmd/teecheck/main.go` (the `expert` subcommand call site)
- Test: `tee-usage-scanner/internal/expert/context_test.go` (+ any expert test calling Run)

**Interfaces:**
- Produces: `expert.RunWithEvents(cfg config.Config, client llm.Client, rec events.Recorder, blobs *events.BlobStore) error`. If a plain `expert.Run(cfg)` wrapper exists, change it to `expert.Run(cfg, client)` and have it call `RunWithEvents(cfg, client, nil, nil)`.

- [ ] **Step 1: Update tests first**

In `context_test.go` and any expert test that runs the agent in heuristic mode: replace the `ExpertMode/Mode: "heuristic"` construction + `expert.Run(...)`/`RunWithEvents(...)` with an injected `&llmtest.FakeClient{Responses: []string{<valid hypothesis JSON the test asserts on>}}`. Keep assertions on the written `hypothesis-*.json` / `ctx.invariants` etc.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/expert/ -v`
Expected: FAIL to compile (signature mismatch / `buildHypothesisHeuristic` undefined once removed).

- [ ] **Step 3: Apply production edits**

`run.go`:
- Signature: `func RunWithEvents(cfg config.Config, client llm.Client, rec events.Recorder, blobs *events.BlobStore) error`.
- Delete `var client llm.Client; if EqualFold(cfg.ExpertMode,"llm"){client=llm.NewClient(cfg)}` (lines ~43-46) — `client` now comes in as a param.
- Replace the per-case branch (lines ~64-72):
  ```go
  var hypothesis artifacts.Hypothesis
  if strings.EqualFold(cfg.ExpertMode, "llm") {
      hypothesis, err = buildHypothesisLLM(...)
      ...
  } else {
      hypothesis = buildHypothesisHeuristic(pack, caseCtx, cfg.AgentID)
  }
  ```
  with always-LLM:
  ```go
  hypothesis, err := buildHypothesisLLM(context.Background(), client, toolAdapter, manifest.LocalPath, pack, caseCtx, cfg.AgentID, cfg.LLMTemp)
  if err != nil {
      return fmt.Errorf("expert llm for %s: %w", pack.CaseID, err)
  }
  ```
- Delete the `buildHypothesisHeuristic` function.
- If `Run(cfg)` exists as a wrapper, update to `Run(cfg, client)` → `RunWithEvents(cfg, client, nil, nil)`.

`pipeline/run.go`: `expert.RunWithEvents(stageCfg, client, rec, blobs)`.
`cmd/teecheck/main.go`: the `expert` subcommand — construct `client := llm.NewClient(cfg)` and pass to the expert Run call.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/expert/ ./cmd/teecheck/ && go test ./internal/expert/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/expert/ tee-usage-scanner/internal/pipeline/run.go tee-usage-scanner/cmd/teecheck/main.go
git commit -m "refactor(expert): drop heuristic hypothesis, inject llm.Client"
```

---

## Task 5: Challenger — drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/challenger/run.go`, `phase1.go`
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (2 call sites — lines ~211 and ~227)
- Modify: `tee-usage-scanner/cmd/teecheck/main.go` (`challenge` subcommand)
- Test: `tee-usage-scanner/internal/challenger/phase1_test.go` (+ any challenger test running the agent)

**Interfaces:**
- Produces: `challenger.Run(cfg config.Config, client llm.Client) error`. Internal helpers `buildIndependentViewLLM`/`buildChallengeLLM` already take `client`.

- [ ] **Step 1: Update tests first**

In `phase1_test.go` and any challenger test using `ChallengeMode: "heuristic"`: inject `&llmtest.FakeClient{Responses: []string{<independent-view JSON>, <challenge JSON>}}` (phase 1 then phase 2 produce two LLM calls) and call `challenger.Run(cfg, fake)`. Assert on the written independent-view / challenge artifacts.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/challenger/ -v`
Expected: FAIL to compile.

- [ ] **Step 3: Apply production edits**

`run.go`: signature `func Run(cfg config.Config, client llm.Client) error`; delete the `var client; if EqualFold(cfg.ChallengeMode,"llm"){client=NewClient}` block; replace each `if EqualFold(cfg.ChallengeMode,"llm"){ ...LLM... } else { ...Heuristic... }` (phase-1 independent view AND phase-2 challenge) with the always-LLM path; delete the heuristic builder helpers (`buildIndependentViewHeuristic`/`buildChallengeHeuristic` or whatever they are named — identify in the file).
`phase1.go`: remove any `ChallengeMode` heuristic branch there.
`pipeline/run.go`: both `challenger.Run(stageCfg)` call sites → `challenger.Run(stageCfg, client)`.
`cmd/teecheck/main.go`: `challenge` subcommand constructs+passes client.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/challenger/ ./cmd/teecheck/ && go test ./internal/challenger/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/challenger/ tee-usage-scanner/internal/pipeline/run.go tee-usage-scanner/cmd/teecheck/main.go
git commit -m "refactor(challenger): drop heuristic, inject llm.Client"
```

---

## Task 6: Verifier — drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/verifier/run.go`
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (lines ~215 `RunWithBusAndEvents`, ~231 `Run`)
- Modify: `tee-usage-scanner/cmd/teecheck/main.go` (`verifier` subcommand)
- Test: any `verifier/*_test.go` that calls `Run`/`RunWithBus*` or uses `VerifierMode: "heuristic"`

**Interfaces:**
- Produces: `verifier.Run(cfg, client) error`, `verifier.RunWithBus(cfg, client, bus) error`, `verifier.RunWithBusAndEvents(cfg, client, bus, rec) error`. `buildMemoLLM` already takes `client`.

- [ ] **Step 1: Identify the heuristic branch, then update tests first**

Read `verifier/run.go`: `RunWithBusAndEvents` already does `client := llm.NewClient(cfg)` unconditionally (line ~225), but `func Run(cfg)` (line 23) and `VerifierMode` config suggest a heuristic path somewhere — locate it (a `buildMemoHeuristic` or an `if EqualFold(cfg.VerifierMode,"llm")` branch). Update any verifier test using `VerifierMode:"heuristic"` to inject `&llmtest.FakeClient{Responses: []string{<verification-memo JSON>}}`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/verifier/ -v`
Expected: FAIL to compile.

- [ ] **Step 3: Apply production edits**

All three entry points take `client llm.Client` as a param; delete internal `llm.NewClient(cfg)` construction and any `VerifierMode` heuristic branch + heuristic memo builder. Callers in pipeline/run.go and cmd updated to construct+pass `client`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/verifier/ ./cmd/teecheck/ && go test ./internal/verifier/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/verifier/ tee-usage-scanner/internal/pipeline/run.go tee-usage-scanner/cmd/teecheck/main.go
git commit -m "refactor(verifier): drop heuristic, inject llm.Client"
```

---

## Task 7: Arbiter — verify/drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/arbiter/run.go`, `chain.go` (as needed)
- Modify: `tee-usage-scanner/internal/pipeline/run.go` (lines ~222 `RunWithBus`, ~238 `Run`)
- Modify: `tee-usage-scanner/cmd/teecheck/main.go` (`arbiter` subcommand)
- Test: `arbiter/*_test.go`

**Interfaces:**
- Produces: `arbiter.Run(cfg, client) error`, `arbiter.RunWithBus(cfg, client, bus) error` — ONLY if arbiter actually uses an LLM. See Step 1.

- [ ] **Step 1: Determine whether arbiter uses an LLM at all**

Read `arbiter/run.go` + `chain.go`. `ArbiterMode` defaults heuristic in config, and `chain.go` matched a "heuristic" grep. Determine: does arbiter call `llm.NewClient`/`Generate`? 
- If YES: apply the same DI + delete-heuristic transformation (Steps 2-4 pattern). Add `client llm.Client` to its entry points; pipeline + cmd pass it.
- If NO (arbiter is purely deterministic synthesis and "heuristic" is just a mode label with no LLM path): do NOT add a client param. Instead just remove the dead `ArbiterMode`-based branching/labels so arbiter has a single path. Record which case applied in the report.

- [ ] **Step 2: Update tests first** (per the case from Step 1)

If arbiter uses LLM: migrate arbiter tests using `ArbiterMode:"heuristic"` to inject a fake. If arbiter is deterministic: adjust tests only if they referenced the removed mode branching.

- [ ] **Step 3: Apply edits + Step 4: verify**

Run: `cd tee-usage-scanner && go build ./internal/arbiter/ ./cmd/teecheck/ && go test ./internal/arbiter/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/arbiter/ tee-usage-scanner/internal/pipeline/run.go tee-usage-scanner/cmd/teecheck/main.go
git commit -m "refactor(arbiter): remove heuristic mode branching"
```

---

## Task 8: Report + Feedback(curator) — drop heuristic, inject client

**Files:**
- Modify: `tee-usage-scanner/internal/report/run.go`, `tee-usage-scanner/internal/feedback/run.go`
- Modify: `tee-usage-scanner/cmd/teecheck/main.go` (`report`, `curator`/`feedback` subcommands)
- Test: `report/*_test.go`, `feedback/*_test.go`

**Interfaces:**
- Produces: `report.Run(cfg, client, ...)`; `feedback.RunWithBus(cfg, client, w, bus)` / `feedback.Run(cfg, client, w)` — signatures matching current shape plus a `client` param.

- [ ] **Step 1: Update tests first**

`report`: the current test likely runs heuristic (concatenated) mode. Migrate to inject a fake returning the synthesized report text and assert on it. `feedback`: the curator LLM path — inject a fake returning the curator JSON; keep the archive-to-`learned/` assertions.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tee-usage-scanner && go test ./internal/report/ ./internal/feedback/ -v`
Expected: FAIL to compile.

- [ ] **Step 3: Apply production edits**

`report/run.go`: remove the `if Mode==llm || VerifierMode==llm { synthesized } else { concatenated }` split — keep the synthesized path only; take an injected `client`; delete the concatenated/heuristic branch. (If report legitimately needs a non-LLM concatenation fallback for a real user scenario, STOP and confirm with the controller before deleting — but per spec heuristic is removed.)
`feedback/run.go`: remove the `CuratorMode` heuristic branch + heuristic curator; take injected `client`; keep archive logic.
Update `cmd/teecheck/main.go` `report` and `curator`/`feedback` subcommands to construct+pass `client`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/report/ ./internal/feedback/ ./cmd/teecheck/ && go test ./internal/report/ ./internal/feedback/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/report/ tee-usage-scanner/internal/feedback/ tee-usage-scanner/cmd/teecheck/main.go
git commit -m "refactor(report,feedback): drop heuristic, inject llm.Client"
```

---

## Task 9: Pipeline injection seam + end-to-end fake-client test

**Files:**
- Modify: `tee-usage-scanner/internal/pipeline/run.go`
- Modify: `tee-usage-scanner/internal/pipeline/run_test.go`
- Modify: `tee-usage-scanner/internal/scanner/scan_test.go` (if it uses heuristic mode)

**Interfaces:**
- Consumes: all agent Run signatures from Tasks 2-8.
- Produces: `pipeline.RunWithClient(cfg config.Config, client llm.Client) (runDir string, err error)`; `pipeline.Run(cfg)` delegates as `RunWithClient(cfg, llm.NewClient(cfg))`.

- [ ] **Step 1: Rewrite the end-to-end test first**

In `run_test.go`, rename `TestPipelineHeuristic` → `TestPipelineEndToEnd_FakeClient`. Set `cfg.Mode = "llm"`. Build a `fake := &llmtest.FakeClient{Responses: []string{...}}` (or `Default:`) whose queued answers are valid-enough JSON for each LLM stage the L3 path invokes (architecture, invariants, planner, expert, challenger×2, verifier, arbiter-if-LLM) so the pipeline runs to completion. Call `pipeline.RunWithClient(cfg, fake)`. Keep the existing artifact-existence assertions (profile, architecture, invariants, graph, arbiter findings). If constructing per-stage canned answers proves impractical for a stage, use a permissive `Default` that each stage's parser tolerates, and assert only the plumbing/artifacts that are reachable — note in the report which stages were exercised.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd tee-usage-scanner && go test ./internal/pipeline/ -run TestPipelineEndToEnd_FakeClient -v`
Expected: FAIL — `RunWithClient` undefined.

- [ ] **Step 3: Add the seam**

In `pipeline/run.go`: rename the existing `func Run(cfg config.Config) (runDir string, err error)` body to `func RunWithClient(cfg config.Config, client llm.Client) (runDir string, err error)`, and remove the local `client := llm.NewClient(cfg)` line introduced in Task 2 (the client is now the param). Add a thin `func Run(cfg config.Config) (string, error) { return RunWithClient(cfg, llm.NewClient(cfg)) }`. Confirm every agent stage call uses the `client` param and that both the L3 and legacy-scanner branches pass it to the agent stages that need it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd tee-usage-scanner && go build ./internal/pipeline/ && go test ./internal/pipeline/ ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tee-usage-scanner/internal/pipeline/ tee-usage-scanner/internal/scanner/scan_test.go
git commit -m "refactor(pipeline): RunWithClient seam + fake-client end-to-end test"
```

---

## Task 10: Remove Mode/sub-mode config + `-mode` CLI heuristic semantics

**Files:**
- Modify: `tee-usage-scanner/internal/config/config.go`
- Modify: any file still referencing a removed `*Mode` field (compiler will name them)
- Test: `tee-usage-scanner/internal/config/*_test.go`

- [ ] **Step 1: Confirm no production code still reads the sub-mode fields**

Run: `cd tee-usage-scanner && grep -rn "ExpertMode\|ChallengeMode\|VerifierMode\|ArbiterMode\|CuratorMode" --include="*.go" . | grep -v _test.go`
Expected after Tasks 4-8: only `config.go` (definitions/defaults/flip block). If any agent still reads one, that agent's task was incomplete — fix there.

- [ ] **Step 2: Apply edits**

`config.go`:
- Delete the struct fields `ExpertMode`, `ChallengeMode`, `VerifierMode`, `ArbiterMode`, `CuratorMode`.
- Delete their default assignments (config.go:107-111, 301, 336, 371, 408, 445) and the `if cfg.Mode == "llm" { cfg.ExpertMode = "llm"; ... }` flip block (config.go:616-621).
- `Mode`: keep the field (still selects L3-vs-legacy in pipeline). For the `report` `-mode` flag (config.go:492, "llm (synthesized) or heuristic (concatenated)") — since report is synthesized-only now, either drop that flag or restrict its help text to remove "heuristic". For the run/scan `-mode` (config.go:562) — keep as the L3-vs-legacy selector; update its help text to drop "heuristic". Do not remove `Mode` itself.

- [ ] **Step 3: Fix compiler-named references + run config tests**

Run: `cd tee-usage-scanner && go build ./... 2>&1 | head` — fix each named reference to a deleted field (should only be test setups that set `ExpertMode:` etc. — remove those lines). Then `go test ./internal/config/ -v`.
Expected: build clean, config tests PASS.

- [ ] **Step 4: Commit**

```bash
git add tee-usage-scanner/internal/config/
git commit -m "refactor(config): remove agent sub-mode fields and -mode heuristic semantics"
```

---

## Task 11: Straggler sweep + full-suite verification

**Files:**
- Possibly modify: `preprocessor/run.go`, `twecontext/context.go`, `repomap/run.go`, `stats/*.go`, `artifacts/types.go`, `planner/actions/legacy_keyword_scan.go` (only if they contain real heuristic logic, not just comments/strings).

- [ ] **Step 1: Grep for remaining heuristic references**

Run: `cd tee-usage-scanner && grep -rn "heuristic\|Heuristic" --include="*.go" internal/ cmd/ | grep -v _test.go`
For each hit: if it is a real heuristic logic branch or a `-mode` remnant, remove it; if it is a doc comment, a string in unrelated output, or an artifact field name (`artifacts/types.go` may have a legitimately-named field), leave it and note why in the report. Do NOT rename data/artifact fields that are part of a persisted schema.

- [ ] **Step 2: Build + vet + full test suite**

Run: `cd tee-usage-scanner && go build ./... && go vet ./... && go test ./...`
Expected: build clean, vet clean, all packages PASS. Fix any straggler test still referencing a removed symbol.

- [ ] **Step 3: Confirm benchmark unaffected**

Run: `cd teecheck-benchmark && go build ./...`
Expected: success.

- [ ] **Step 4: go mod tidy + commit**

```bash
cd tee-usage-scanner && go mod tidy
cd /root/pp_home/idea/TEECheck
git add -A
git commit -m "chore: remove heuristic stragglers + verify full suite green"
```

---

## Self-Review Notes (coverage vs spec)

- Spec §3.1 (architecture/invariants) → Tasks 2, 3.
- Spec §3.2 (expert/challenger/verifier/report/feedback internal-construct) → Tasks 4, 5, 6, 8.
- Spec §3.3 (arbiter/preprocessor/twecontext/repomap/stats verify) → Tasks 7, 11.
- Spec §4.1-4.2 (DI + orchestration constructs client) → each agent task + Task 9.
- Spec §4.3 (8 test migrations to fake) → Tasks 2,3,4,5,6,8,9 (per package); shared fake = Task 1.
- Spec §4.4 (config/CLI cleanup) → Task 10.
- Spec §4.5-4.6 (E2E test llm-mode fake + heuristic/legacy decoupling) → Task 9.
- Spec §6 acceptance 1-6 → Tasks 10/11 (no heuristic remains), each agent task (DI), 9 (E2E), 11 (build/vet/test/benchmark + grep sweep).
