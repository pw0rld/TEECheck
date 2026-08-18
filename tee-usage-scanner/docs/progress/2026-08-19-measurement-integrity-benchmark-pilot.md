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

## Current Status

`IN PROGRESS`: measurement-integrity repair pass.

## Verification Ledger

| Area | Red evidence | Green evidence | Status |
|---|---|---|---|
| Empty findings array | Pending | Pending | Not started |
| Findings validation | Pending | Pending | Not started |
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

