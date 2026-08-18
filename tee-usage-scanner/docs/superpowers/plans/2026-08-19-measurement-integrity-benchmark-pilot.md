# Measurement Integrity and Benchmark Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make TEECheck run artifacts reproducible and machine-validatable, then execute and classify a six-pair benchmark pilot.

**Architecture:** Stabilize wire contracts in `internal/artifacts`, validate complete run bundles in a new `internal/runvalidate` package, add native Responses transport under `internal/llm`, and make reporting preserve deterministic inventories and coverage. Runtime fixes remain within the executor, planner, and Repomix ownership boundaries.

**Tech Stack:** Go 1.25, JSON Schema, CodeQL artifacts, OpenAI Responses/Chat Completions HTTP APIs, Go tests.

---

### Task 1: Lock the baseline and empty-findings contract

**Files:**
- Modify: `internal/arbiter/run.go`
- Test: `internal/arbiter/run_test.go`
- Create: `internal/schema/schemas/findings.v2.json`
- Test: `internal/schema/schema_test.go`

- [ ] Add a failing arbiter test asserting a zero-result run decodes as a non-nil, zero-length `findings` array.
- [ ] Run `go test ./internal/arbiter -run EmptyFindings -count=1` and verify it fails with `findings` serialized as `null`.
- [ ] Initialize `Findings` with `make([]artifacts.FindingItem, 0)` at the arbiter boundary.
- [ ] Add the actual `teecheck.findings.v2` container schema with closed status, severity, and confidence enums.
- [ ] Run arbiter and schema tests and verify they pass.

### Task 2: Validate finding values before persistence

**Files:**
- Create: `internal/artifacts/findings_validate.go`
- Test: `internal/artifacts/findings_validate_test.go`
- Modify: `internal/arbiter/run.go`

- [ ] Add table-driven failing tests for unknown status/severity/confidence and missing finding ID or summary.
- [ ] Implement `func (f Findings) Validate() error` using explicit allowed-value maps.
- [ ] Call validation immediately before writing `07_arbiter/findings.json`; return a stage error on invalid model output.
- [ ] Verify `go test ./internal/artifacts ./internal/arbiter -count=1` passes.

### Task 3: Add run-bundle validation

**Files:**
- Create: `internal/runvalidate/validate.go`
- Create: `internal/runvalidate/validate_test.go`
- Modify: `internal/config/config.go`
- Modify: `cmd/teecheck/main.go`

- [ ] Add failing fixture tests for a valid completed run, missing terminal event, failed terminal event, missing blob, bad blob digest, invalid findings, and absent required stage artifact.
- [ ] Implement structured `Issue{Code, Path, Message}` results without invoking external tools.
- [ ] Validate manifest/run ID consistency, contiguous event sequence, terminal completion, all `sha256:` references, blob hashes, findings contract, and stage outputs implied by emitted stage events.
- [ ] Add `teecheck validate-run --run-dir DIR` with nonzero exit on errors and concise JSON/human output.
- [ ] Verify the two new Terra runs validate and the intentionally interrupted GPT-5.5 run is rejected.

### Task 4: Record actual provenance

**Files:**
- Modify: `internal/artifacts/types.go`
- Modify: `internal/runinit/init.go`
- Modify: `internal/pipeline/run.go`
- Test: `internal/runinit/init_test.go`
- Test: `internal/pipeline/provenance_events_test.go`

- [ ] Add failing tests asserting actual `runtime.Version()`, build VCS revision/dirty state, model/provider/transport, resolved budgets, and CodeQL version/status are recorded without secrets.
- [ ] Replace hard-coded Go/scanner version strings with runtime/build-info discovery and an explicit unknown fallback.
- [ ] Persist resolved non-secret LLM and planner settings in the manifest or a versioned run-config artifact.
- [ ] Record CodeQL version when available and `unavailable` otherwise.
- [ ] Verify API keys remain absent from manifest and events.

### Task 5: Add native Responses API transport

**Files:**
- Create: `internal/llm/responses.go`
- Create: `internal/llm/responses_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/llm_provider.go`
- Modify: `internal/llm/client.go`

- [ ] Add failing HTTP tests for request mapping, `reasoning.effort`, output extraction, usage extraction, incomplete response, provider error, and wire-byte preservation.
- [ ] Add explicit `--llm-transport chat-completions|responses` and `--llm-reasoning-effort` settings.
- [ ] Implement a Responses client behind the existing `llm.Client` interface.
- [ ] Route provider construction by transport while preserving current defaults.
- [ ] Replace the pilot's local proxy with native Responses transport and run the live one-line probe.

### Task 6: Make reports complete by construction

**Files:**
- Modify: `internal/report/run.go`
- Create: `internal/report/run_test.go`

- [ ] Add failing tests proving all finding IDs appear, packet read errors fail, truncation is disclosed, coverage and terminal errors are included, and failed runs are rejected by default.
- [ ] Build deterministic provenance, finding inventory, coverage, truncation, and error sections before optional narrative generation.
- [ ] Replace raw byte-prefix truncation with per-packet bounded excerpts that record omitted byte counts and preserve UTF-8.
- [ ] Verify every finding ID after assembly and return an error if completeness cannot be guaranteed.
- [ ] Run `go test ./internal/report -count=1`.

### Task 7: Repair planner metadata and observability

**Files:**
- Modify: `internal/artifacts/types.go`
- Modify: `internal/pipeline/run.go`
- Modify: `internal/planner/budget.go`
- Test: `internal/pipeline/l3planner_test.go`

- [ ] Add failing multi-sample tests asserting aggregate rounds budget equals the sum of pass budgets and termination reasons remain per pass.
- [ ] Introduce a per-pass metadata array plus aggregate usage/budget fields.
- [ ] Prevent misleading `rounds_used > rounds_budget` output.
- [ ] Promote query failure, response truncation, and unsatisfied recon dimensions into persisted coverage data consumed by reports.
- [ ] Verify existing single-sample artifacts remain readable.

### Task 8: Fix execution timeout and hermetic tests

**Files:**
- Modify: `internal/executor/local.go`
- Test: `internal/executor/local_test.go`
- Modify: `internal/planner/actions/repomix_summarize_test.go`
- Modify: `internal/config/config_test.go`

- [ ] Retain the existing failing descendant-timeout test and confirm the five-second child outlives the 200 ms deadline.
- [ ] On Unix, start commands in a process group and terminate the group on context cancellation; keep portable fallback behavior.
- [ ] Replace the Repomix unit test's live `npx` call with a fake executor and move live behavior behind an opt-in integration environment variable.
- [ ] Isolate provider environment in the dialog-budget config test.
- [ ] Run the affected packages, then `go test ./... -count=1` offline.

### Task 9: Execute the six-pair pilot

**Files:**
- Create: `.omc/artifacts/benchmark-pilot-2026-08-19/selection.json`
- Create: `.omc/artifacts/benchmark-pilot-2026-08-19/results.jsonl`
- Update: `docs/progress/2026-08-19-measurement-integrity-benchmark-pilot.md`

- [ ] Select six pairs from checked-in split metadata without using holdout oracle detail for scanner changes.
- [ ] Record scanner commit, model snapshot/config, selection rationale, and exact commands.
- [ ] Run vulnerable and fixed variants with one sample and no target hint.
- [ ] Validate each run before scoring it.
- [ ] Record top-location match, fixed-side discrimination, detection source, planner/coverage termination, truncation/failure counts, usage, and wall time.
- [ ] Classify each miss using the approved failure taxonomy.

### Task 10: Final verification and report

**Files:**
- Update: `docs/progress/2026-08-19-measurement-integrity-benchmark-pilot.md`

- [ ] Run formatting, static checks, full tests, CLI build, and run-validator checks.
- [ ] Review the diff for secrets, benchmark-answer leakage, unrelated refactors, and ignored artifacts.
- [ ] Summarize completed changes, red/green evidence, pilot results, remaining risks, and prioritized next work.

