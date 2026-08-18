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

### 2026-08-19 05:15 HKT - Pilot command preflight

- RED: the pilot's explicit `--llm-max-tokens 32768` control was rejected
  because the `run` parser initialized this setting from the environment but
  did not register the corresponding CLI flag used by the stage commands.
- GREEN: `run` now exposes the same flag and a focused parser regression proves
  that the resolved configuration retains the requested value. Config tests,
  vet, and diff checks pass.
- This changes configuration plumbing only. Detection logic remains frozen
  before any pilot result is observed.

### 2026-08-19 06:55 HKT - Six-pair Terra-high pilot complete

- Executed 12 sequential scans from 00:57:52 to 02:40:43 HKT using scanner
  revision `7d1b5616e4264d905a833cf0b1b9b283a28e32c1`, CodeQL `2.24.0`, one
  sample, no target hint, native Responses, Terra high reasoning, and an
  explicit 32,768-output-token limit.
- Every run used a pinned full upstream checkout rather than only the fixture
  subset. Every manifest records the repository, revision, source scope, model
  configuration, planner limits, scanner build, and CodeQL version.
- All 12 bundles pass `teecheck validate-run`. Across 205 LLM calls there were
  zero recorded LLM failures, tool failures, or truncations.
- The batch consumed 1,488,350 planner tokens (mean 124,029 per run) and wrote
  approximately 12 GB of artifacts.
- Machine-readable selection, per-run results, raw runner log, and score live
  under `TEECheck/.omc/artifacts/benchmark-pilot-2026-08-19/` and remain
  ignored by Git.

Secret-free command template (the credential was loaded only into
`TEECHECK_LLM_API_KEY` from the ignored local auth file):

```bash
GOCACHE=/tmp/teecheck-gocache go run ./evaluator/runner \
  -cases /tmp/teecheck-benchmark-pilot-20260819-cases -mode evaluate \
  -results ../.omc/artifacts/benchmark-pilot-2026-08-19/runs -timeout 60m \
  -scanner-command "/tmp/teecheck-pilot run {input} --repo-url {repository} --commit {revision} --focus tee --run-id scan --output-dir {run_dir} --knowledge-root /home/payson/Documents/AI4Security/TEE-Usage/TEECheck/tee-usage-scanner/knowledge --max-cases 8 --max-hotspots 8 --samples 1 --llm-provider openai --llm-base-url http://43.110.35.69:8080/v1 --llm-model gpt-5.6-terra --llm-transport responses --llm-reasoning-effort high --llm-timeout-seconds 900 --llm-max-tokens 32768"
```

| Case | Vulnerable score / findings | Fixed score / findings | Pair | Primary pipeline observation |
|---|---:|---:|---:|---|
| `CVE-2019-0876` | FN / 0 | TN / 0 | Fail | Both planners ended reconnaissance without a candidate. |
| `CVE-2020-16273` | FN / 0 | TN / 0 | Fail | Both planners exhausted the aggregate token budget. |
| `CVE-2021-44421` | FN / 0 | TN / 0 | Fail | Both planners exhausted the aggregate token budget. |
| `CVE-2023-42811` | FN / 0 | FP / 1 | Fail | Rust index had zero function-card pages; only the fixed side opened an autonomous candidate. |
| `CVE-2025-46733` | FN / 1 | TN / 1 | Fail | Deterministic lane emitted the same incidental, non-target property on both sides. |
| `CVE-2026-44362` | TP / 1 | TN / 0 | Pass | Deterministic lane caught and discriminated the known rollback control; autonomous planner added no candidate. |

- Target-matching totals are TP=1, FP=1, FN=5, TN=5, precision=0.5000,
  recall=0.1667, F1=0.2500, specificity=0.8333, and paired pass rate 1/6.
- These totals are diagnostic, not a valid in-scope headline metric: all six
  checked-in oracles omit `twe_family`, so the evaluator places every case in
  the out-of-scope track and leaves the in-scope track empty. Inventing those
  classifications during this pilot would invalidate the frozen measurement.
- The scorer uses target-specific matching. `CVE-2025-46733` therefore reports
  FN/TN even though both variants contain one incidental finding; reporting
  must make this distinction more prominent.

### 2026-08-19 07:10 HKT - Benchmark report integrity follow-up

- RED: the scorer derived F1 from already rounded precision/recall and wrote
  `0.250037498125...` instead of the exact count-derived value `0.25`.
- GREEN: F1 now uses `2*TP / (2*TP + FP + FN)`. The focused regression and
  full runner package pass; the pilot score was regenerated without changing
  any case classification.
- The runner suite also exposed a stale knowledge-layout assumption. Its
  holdout-leak guard now recursively scans every YAML file under the current
  `knowledge/twe` tree rather than requiring a removed `playbooks` directory.

### 2026-08-19 07:30 HKT - Final verification

- Scanner: `GOCACHE=/tmp/teecheck-gocache go test ./... -count=1`, `go vet
  ./...`, and a fresh `cmd/teecheck` build all pass. `internal/repoindex` was
  the longest package at 149.6 seconds.
- Benchmark: full tests, `go vet ./...`, and a fresh evaluator-runner build all
  pass.
- Benchmark vet initially exposed `testing.T.Context()` despite the module's
  declared Go 1.23 compatibility. The test now uses `context.Background()`;
  no production behavior changed.
- `git diff --check`, tracked-diff credential scan, selection JSON validation,
  and all 12 JSONL result records pass.
- All 12 pilot run bundles were revalidated after execution and remain valid.

## Current Status

`COMPLETE`: measurement-integrity repair and six-pair diagnostic pilot.

The pipeline is operational and its run artifacts are now reproducible,
complete, and machine-validatable. Current detection capability is narrow: it
reliably discriminates the demonstrated deterministic rollback control, but
this pilot provides no evidence that the Terra-driven autonomous planner can
discover an unseen vulnerable target. General benchmark readiness requires the
P0 items below.

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
| CodeQL provenance | CodeQL version/status absent | Recorded probe reports `2.24.0` in all pilot manifests | Complete |
| Pilot run integrity | No cross-run validation evidence | All 12 bundles validate; zero LLM/tool failures or truncations | Complete |
| Benchmark arithmetic | Rounded inputs produced imprecise F1 JSON | Count-derived F1 regression and regenerated score | Complete |

## Pilot Ledger

Pilot execution and validation are complete. Authoritative ignored artifacts:

- `selection.json`: frozen selection and secret-free controls.
- `results.jsonl`: 12 normalized per-variant records.
- `runner.log`: complete sequential execution log.
- `runs/score.json` and `runs/score.md`: target-matching evaluator output.
- `runs/<case>/<variant>/scan/`: complete scanner bundle for each variant.

## Prioritized Improvements

1. **P0 - Restore a defensible capability track.** Add sourced scope/family
   metadata or a separate reviewed property-family annotation layer, validate
   its completeness before scoring, and refuse to publish an in-scope headline
   when the selected set contains zero classified in-scope cases.
2. **P0 - Repair autonomous discovery economics.** Separate reconnaissance and
   investigation token budgets, reserve budget for `open_audit_lead`/`done`,
   stop repeating unchanged repository context, and add a completion policy
   that prevents 8/12 runs from ending only because aggregate input tokens
   crossed 120,000. The current planner opened just one candidate across all 12
   runs, and that candidate occurred on a fixed variant.
3. **P0 - Tighten deterministic fact promotion.** Record why a fact is relevant
   to the active property, carry negative/guard evidence into promotion, and
   test non-differential paired revisions. The same incidental rollback signal
   survived on both sides of `CVE-2025-46733` despite not matching that target.
4. **P1 - Make index coverage explicit and actionable.** Emit language,
   extractor, module, symbol, function-card, and unsupported-file coverage in a
   versioned artifact. Zero Rust function-card pages must be a visible partial
   coverage state, not merely a console line.
5. **P1 - Separate target score from incidental findings.** Add explicit
   `target_observed`, `total_findings`, and `incidental_findings` fields so a
   target-specific TN with one unrelated finding is never summarized simply as
   `clean`.
6. **P1 - Reduce paired-run cost.** Cache immutable source clones and CodeQL
   packs safely by repository/revision/tool version, add disk preflight and
   cleanup policy, and retain only the database data needed for replay. The
   first Open Enclave extraction temporarily exceeded 6 GB and dominated run
   time.
7. **P2 - Measure stability.** After P0 fixes, repeat a small balanced set with
   at least three seeds/samples and report candidate/finding agreement. The
   RustCrypto fixed-only candidate shows that one-sample results are not enough
   to characterize model behavior.

## Open Risks

- All selected oracles currently lack TWE-family metadata, so the evaluator's
  in-scope capability track is empty.
- Planner prompt input dominates its aggregate token budget; 11/12 runs ended
  in `max_tokens` or `recon_incomplete` and no vulnerable run gained an
  autonomous candidate.
- The deterministic OP-TEE control proves target-specific discrimination but
  not blind generalization.
- Rust indexing can produce modules with zero function-card pages without
  elevating the run to a partial-coverage status.
- One sample per variant cannot quantify LLM variance.
- The local model credential remains stored only under ignored `.omc/local/`
  with mode `0600`; it must never enter tracked files or test fixtures.
