# TEECheck Measurement Integrity and Benchmark Pilot Progress Log

## Objective

Repair defects that make benchmark output misleading or non-reproducible, then
run a small diverse benchmark pilot and classify failures by pipeline stage.

## Baseline

- Scanner revision: `4b50560372ebf61fca1269b98d33a2cd0012f0ed`
- Vulnerable control run: `scan-current-terra-high-vuln`
- Fixed control run: `scan-current-terra-high-fixed`
- Model: `gpt-5.6-terra`, reasoning effort `high`
- Vulnerable control: one deterministic target finding, `needs_review`, high,
  medium confidence.
- Fixed control: zero findings, serialized incorrectly as `null`.
- Planner produced zero autonomous candidates on both sides and terminated on
  aggregate token budget.
- One vulnerable-side verifier response was truncated from 294,069 bytes to
  32,768 bytes.
- New-run blob integrity: 303/303 hashes valid; all event references resolved.

## Work Log

### 2026-08-19 00:00 HKT - Planning and baseline lock

- Approved staged hybrid approach recorded in the design document.
- Test-first implementation plan created.
- Existing unrelated worktree entry `.omx/` noted and left untouched.
- Three read-only mapping lanes started for artifact contracts, transport/report,
  and runtime reliability.

### 2026-08-19 00:20 HKT - Empty findings contract

- RED: `TestRunWithBus_EmptyFindingsSerializesArray` failed because a zero-case
  arbiter result decoded `findings` as nil.
- GREEN: the arbiter now initializes the collection explicitly; the focused
  regression passes and emits an empty JSON array.

### 2026-08-19 00:45 HKT - Findings validation and schema

- RED: model output with `status=invented_status` was persisted successfully;
  the focused arbiter regression demonstrated the missing validation gate.
- GREEN: `Findings.Validate` now enforces the v2 schema version, non-null array,
  required identifiers/summary, and closed status/severity/confidence values.
- Added canonical and embedded `findings.v2.json` schemas with drift tests.
- Verification: `go test ./internal/artifacts ./internal/schema ./internal/arbiter
  -count=1` passes.

### 2026-08-19 01:20 HKT - Run-bundle integrity validator

- RED: focused tests had no `runvalidate.Validate` implementation and the CLI
  rejected the new `validate-run` command.
- GREEN: added a deterministic, offline validator for manifest/run identity,
  JSONL parsing and contiguous sequence numbers, paired stage lifecycle events,
  successful terminal state, content-addressed blob presence and hashes,
  required outputs for completed stages, and the findings Go/JSON-Schema
  contracts.
- Added `teecheck validate-run --run-dir DIR`; it emits a structured JSON report
  and exits nonzero for invalid bundles.
- Empirical check: `scan-current-terra-high-vuln` passes with zero issues.
  `scan-current-terra-high-fixed` is rejected with `findings_contract` and
  `findings_schema` because its historical zero result serialized as `null`.
- Focused verification passes for `internal/runvalidate`, the new config parser
  regression, `cmd/teecheck`, and a fresh CLI build.
- The wider config package still fails its already-recorded ambient-environment
  test; that remains assigned to the runtime/test-hermeticity pass.

### 2026-08-19 01:55 HKT - Build, model, and budget provenance

- RED: the manifest still reported `teecheck=harness-prototype` and
  `go=1.25.0`; it had no build, transport, reasoning-effort, resolved LLM, or
  planner-limit fields. The main `run` parser also discarded transport and
  reasoning environment settings.
- GREEN: manifests now contain actual Go build metadata (version, Go version,
  VCS revision, modified state), secret-free resolved run/LLM configuration,
  and the planner's real aggregate limits.
- The API key is never persisted. A boolean records only whether a credential
  was present, allowing an operator to distinguish an authenticated run from a
  missing-credential setup without leaking the credential.
- `run` now resolves `TEECHECK_LLM_TRANSPORT` / `--llm-transport` and
  `TEECHECK_LLM_REASONING_EFFORT` / `--llm-reasoning-effort`.
- Fresh build metadata reports the repository VCS revision and dirty state;
  focused run-init, pipeline, config, and artifact tests pass.

### 2026-08-19 02:40 HKT - Native Responses transport

- RED: Responses-focused client tests reached `/chat/completions`; incomplete
  Responses envelopes lost their usage accounting and produced a generic parse
  error.
- GREEN: the OpenAI client now dispatches explicitly between the compatible
  Chat Completions default and native Responses. Responses requests persist raw
  request/response bytes, send `store=false`, apply the configured reasoning
  effort and output-token limit, support JSON mode, and preserve usage on
  incomplete responses.
- Startup validation rejects unknown transports/reasoning levels and rejects
  reasoning settings that would not be transmitted.
- First live Terra-high run: basic and JSON checks passed; the agent-style JSON
  request received HTTP 400 because this endpoint requires the word `json` in
  an input message, while the native client had put the system prompt in the
  separate `instructions` field.
- RED/GREEN follow-up: system prompts now travel as `role=system` input messages,
  matching the previously working proxy wire shape. A second direct live run
  passed basic connectivity, JSON output, and the agent-style structured query
  in 17.31 seconds. The compatibility proxy is no longer required for Terra.

### 2026-08-19 03:15 HKT - Deterministic report completeness

- RED: a fake narrative that named only one of two findings became the entire
  report; evidence, the other finding, planner metrics, and packet content past
  8 KB were absent. A provider error aborted report generation completely.
- GREEN: `findings.json` is now the authoritative report source. Every finding
  is deterministically sorted and rendered with locations, evidence, and all
  structured arbiter sections. Planner metrics and every review packet are
  appended without truncation.
- The model is restricted to a labeled, non-authoritative two-paragraph
  narrative over bounded finding summaries. Provider failure falls back to an
  offline narrative notice and still writes the factual report.
- Real-artifact smoke check: the vulnerable Terra control produced a 20,103-byte
  offline report containing its deterministic finding in both index and detail;
  the complete 5,415-byte review packet is embedded.

### 2026-08-19 04:05 HKT - Runtime and test reliability

- Executor RED: a command with a 200 ms timeout returned after 5.00 seconds
  because the shell was killed while its child retained the output pipes.
- Executor GREEN: Unix commands now run in their own process group and context
  cancellation kills the group. The same test completes in 0.20 seconds; the
  timeout event regression also passes.
- Planner accounting RED: multi-sample merge summed rounds/tokens but retained
  only pass 1's round budget, termination reason, truncation state, and errors.
- Planner accounting GREEN: aggregate budgets and usage now sum consistently;
  `termination_reason=multi_sample` is explicit, and per-pass rounds, budgets,
  tokens, wall time, termination, and truncation are preserved.
- Coverage visibility: the final report now renders coverage-ledger totals,
  per-sample recon status and actions, and the full unreviewed-cluster list.
- Hermeticity: the dialog-budget test now declares its provider prerequisites;
  Repomix unit tests use the existing fake-`npx` harness; non-Git local sources
  no longer treat commit `unknown` as a checkout target; pipeline fixtures are
  copied outside the parent Git repository.
- Combined verification passes for executor, pipeline, report, stats, config,
  Repomix, and planner actions. The pipeline package completed in 54.5 seconds
  without a network acquisition attempt.

### 2026-08-19 04:35 HKT - Full code-change verification gate

- `GOCACHE=/tmp/teecheck-gocache go test ./... -count=1`: PASS across every
  package. The longest package (`internal/repoindex`) completed in 149.2 seconds;
  the full run exited zero.
- `GOCACHE=/tmp/teecheck-gocache go vet ./...`: PASS.
- Fresh `cmd/teecheck` build: PASS.
- `git diff --check`: PASS.
- Worktree contains no uncommitted scanner source changes at this checkpoint;
  the unrelated parent `../.omx/` entry remains untouched.

### 2026-08-19 05:00 HKT - CodeQL provenance gate

- RED: the manifest recorded the scanner and Go versions but omitted CodeQL,
  so a benchmark result could not prove which deterministic analysis engine
  produced its repository index.
- GREEN: the CodeQL engine now probes `version --format=json` through the
  run's recording executor and persists the normalized version in
  `tool_versions.codeql`. Unavailable and failed probes are represented
  explicitly as `unavailable` and `error` rather than silently omitted.
- The installed pilot engine reports CodeQL `2.24.0`.
- Focused CodeQL, run-initialization, and pipeline tests pass; the pipeline
  package completed in 58.1 seconds.

## Current Status

`IN PROGRESS`: measurement-integrity repair pass.

## Verification Ledger

| Area | Red evidence | Green evidence | Status |
|---|---|---|---|
| Empty findings array | Nil slice reproduced in focused arbiter test | Focused arbiter regression passes | Complete |
| Findings validation | Invalid status persisted in focused arbiter test | Artifact, schema, and arbiter packages pass | Complete |
| Run validator | Missing implementation/CLI reproduced by focused tests | Synthetic corruptions rejected; vulnerable control valid; fixed control rejects historical null | Complete |
| Provenance | Hard-coded versions and absent model/budget/CodeQL controls reproduced | Actual build/VCS, resolved LLM controls, planner limits, and CodeQL version/status verified in manifest | Complete |
| Responses transport | Native tests hit chat path; live JSON agent request reproduced provider input constraint | Unit suite and all three direct Terra-high live checks pass | Complete |
| Report completeness | Fake narrative omitted one of two findings and provider failure aborted output | Deterministic completeness/fallback tests and real vulnerable-control smoke pass | Complete |
| Planner accounting | Mixed aggregate/pass-1 metadata reproduced | Aggregate and per-pass accounting regression passes | Complete |
| Executor timeout | 200 ms timeout returned after 5.00 s | Process-group cancellation returns in 0.20 s | Complete |
| Offline full suite | Config, executor, Repomix, and pipeline acquisition leaks observed | Full test suite, vet, build, and diff check pass | Complete |

## Pilot Ledger

Pilot execution is gated on the measurement-integrity checklist in the design
document. No pilot result will be treated as valid before its run bundle passes
the new validator.

## Open Risks

- Native Responses support may expose provider-specific response differences.
- Planner prompt input dominates its aggregate token budget even when Terra
  returns short, valid actions.
- The deterministic OP-TEE fixture proves target-specific discrimination but
  does not measure blind generalization.
- The local model credential remains stored only under ignored `.omc/local/`
  with mode `0600`; it must never enter tracked files or test fixtures.
