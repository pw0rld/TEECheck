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

## Current Status

`IN PROGRESS`: measurement-integrity repair pass.

## Verification Ledger

| Area | Red evidence | Green evidence | Status |
|---|---|---|---|
| Empty findings array | Nil slice reproduced in focused arbiter test | Focused arbiter regression passes | Complete |
| Findings validation | Invalid status persisted in focused arbiter test | Artifact, schema, and arbiter packages pass | Complete |
| Run validator | Pending | Pending | Not started |
| Provenance | Pending | Pending | Not started |
| Responses transport | Pending | Pending | Not started |
| Report completeness | Pending | Pending | Not started |
| Planner accounting | Pending | Pending | Not started |
| Executor timeout | Existing 200 ms test takes about 5 s | Pending | Confirmed defect |
| Offline full suite | Config, executor, and Repomix failures observed | Pending | Confirmed defect |

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
