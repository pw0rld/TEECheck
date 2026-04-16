# MobileCoin L3 Audit Report — v22 (Multi-Sample)

**Target:** `mobilecoinfoundation/mobilecoin` @ `59a52d3d52e6`
**Focus:** TEE (attestation + key lifecycle)
**Date:** 2026-04-16
**Pipeline:** L3 planner (5 independent passes with avoid-list) + 4-agent adversarial review (GLM-4.7)
**First multi-sample audit run.** 5 planner passes discovered 11 unique candidates across 7 crates — 3.7x the coverage of any single-sample run in v1–v20.

## TL;DR

v22 is the first run using `--samples 5`, which runs the planner 5 times with an avoid-list that grows after each pass. The LLM correctly explored new code paths each time (0 dedup collisions). Combined with the verifier snippet-injection fix from v20, this produces the broadest and most grounded audit report in the series.

**By the numbers:**
- 11 unique candidates (vs 3 in any single-sample run)
- 7 distinct crates covered (attest/, crypto/, consensus/, sgx/, fog/)
- 3/11 verifier-corroborated (against real code)
- 2 `confirmed_candidate` (high confidence) + 1 `likely_issue`
- `reverse_trace` used autonomously in 2 of 5 passes
- Total planner cost: 66k tokens / 411s wall clock

## Planner Passes

| Pass | Candidates | New Avoid Targets | Key Crates Hit |
|---|---|---|---|
| 1 | 2 | 0 → 8 | `attest/ake/`, `crypto/ake/enclave/` |
| 2 | 2 | 8 → 17 | `consensus/enclave/`, `attest/core/` |
| 3 | 3 | 17 → 19 | `sgx/service/`, `attest/verifier/` |
| 4 | 2 | 19 → 22 | `sgx/service/` (seal/unseal + report creation) |
| 5 | 3 | 22 → 27 | `attest/trusted/`, `sgx/types/` |
| **Total** | **12 raw → 11 unique** | | **7 crates** |

`reverse_trace` was used in passes 1 and 2 — the LLM autonomously traced backward from `verify_attestation_evidence` to find the AKE responder and consensus enclave integration points.

## All 11 Findings

### Tier 1 — Confirmed Candidates (2, high confidence)

#### Finding 001 — AKE Responder skips attestation on `ClientAuthRequestInput`
**File:** `attest/ake/src/responder.rs`
**Verifier:** corroborated
**Arbiter:** confirmed_candidate (high)

The `ClientAuthRequestInput` transition path deserializes the incoming payload but **skips the critical attestation verification step** (checking quote + collateral) before proceeding to the handshake response. This creates an unauthenticated mode in the AKE responder — a client that sends `ClientAuthRequestInput` instead of `AuthRequestInput` bypasses attestation entirely.

**Evidence (from verifier against real code):**
- The `try_next` method has two match arms: one for `AuthRequestInput` (which calls `verifier.verify()`) and one for `ClientAuthRequestInput` (which does NOT)
- The `ClientAuthRequestInput` path proceeds directly to `handle_response` → `Ready` state
- This is consistent with the code comment at lines 189–201 referencing "unauthenticated" modes

**Human check:** Is `ClientAuthRequestInput` reachable in production? If it's a test-only path, this is low-risk. If any production client can trigger it, this is a real bypass.

#### Finding 006 — `verify_report` wrapper hides report fields from caller
**File:** `sgx/service/src/lib.rs`
**Verifier:** corroborated
**Arbiter:** confirmed_candidate (high)

The `verify_report` function wraps `sgx_verify_report` (FFI) and returns only `sgx_status_t` — it does **not** expose the report's `MRENCLAVE`, `MRSIGNER`, `REPORT_DATA`, or `ATTRIBUTES` fields to the caller. This means a caller who uses `verify_report` can confirm "this report has a valid signature" but **cannot inspect what the report actually claims** (which enclave produced it, what data it bound, whether debug mode was on).

**Evidence:**
- Function signature returns `Result<(), SgxError>` — no report body
- Callers must separately call `sgx_create_report` and compare fields manually — this is not enforced by the API
- The `report()` function (which generates reports) also accepts `report_data: Option<&sgx_report_data_t>` where `None` means "no binding"

**Human check:** Trace all callers of `verify_report` — do they separately inspect the report body, or do they trust the `Ok(())` alone?

### Tier 2 — Likely Issue (1, medium confidence)

#### Finding 005 — `Quote::verify` implementation not visible in snippet
**File:** `attest/core/src/quote.rs`
**Verifier:** corroborated
**Arbiter:** likely_issue (medium)

The case pack included the first 190 lines of `quote.rs` (type definitions and constructors). The actual `verify()` and `verify_report()` implementations start at line 279+. The verifier confirmed the types and structure but could not evaluate the verification logic. The hypothesis (missing freshness/identity checks in quote verification) remains open — evidence is incomplete, not refuted.

**Human check:** Read `attest/core/src/quote.rs` lines 279–400 and check for nonce/timestamp validation.

### Tier 3 — Needs Review (8, low confidence)

These findings share a common pattern: the **code visible in snippets is a delegation boundary** (calling `self.ake.verify_*` or `verifier.verify()`), and the actual logic lives in another crate. The verifier correctly identified this but couldn't resolve it without cross-file context.

| # | File | Core observation |
|---|---|---|
| 002 | `crypto/ake/enclave/src/lib.rs` | `peer_init` implementation not in snippet |
| 003 | same | MRENCLAVE check delegated to invisible `get_verifier` |
| 004 | `consensus/enclave/impl/src/lib.rs` | attestation delegated to `self.ake`, no visible validation of result |
| 007 | `attest/verifier/src/dcap.rs` | Core verification delegated to `mc_attestation_verifier` external crate |
| **008** | `sgx/service/src/lib.rs` | **Sealing uses `SGX_KEYPOLICY_MRENCLAVE` (strict)** — this is actually a positive finding, not a vulnerability |
| 009 | `sgx/service/src/lib.rs` | `report()` allows `report_data=None` → generates unbound report |
| 010 | `attest/trusted/src/lib.rs` | `report_data` not checked for freshness/replay |
| 011 | `sgx/types/src/{function,types}.rs` | Only FFI declarations, no implementation to audit |

### Notable: Finding 008 answers a prior open question

v20 Finding 2 flagged `fog/ingest/enclave/impl/src/lib.rs::enclave_init` for "no visible MRENCLAVE check on unseal". We couldn't resolve it without knowing the sealing policy. v22's planner independently entered `sgx/service/src/lib.rs::seal_data` and the verifier confirmed:

> "The code strictly enforces `SGX_KEYPOLICY_MRENCLAVE`, which binds sealed data to the exact enclave measurement."

This means v20 Finding 2 is **not a vulnerability** — the hardware sealing policy provides the MRENCLAVE binding that the application code doesn't need to re-check. v22 closed this question without any human intervention, simply by expanding coverage to include the seal implementation.

## Coverage Map

Directories touched across all 5 passes (✓ = candidate found, ✗ = not reached):

```
attest/
  ├── ake/src/          ✓ responder (pass 1)
  ├── core/src/         ✓ quote (pass 2)
  ├── trusted/src/      ✓ report (pass 5)
  └── verifier/src/     ✓ dcap (pass 3)
crypto/
  └── ake/enclave/src/  ✓ session binding (pass 1) + verify (pass 2)
consensus/
  └── enclave/impl/src/ ✓ attestation integration (pass 2)
sgx/
  ├── service/src/      ✓ verify_report + seal + report creation (passes 3-4)
  └── types/src/        ✓ key derivation FFI (pass 5)
fog/
  ├── ingest/           ✗ (covered in v20/v21, not re-hit in v22)
  ├── view/             ✗
  ├── ledger/           ✗
  └── enclave_connection/ ✗
enclave-boundary/       ✗
```

5 of 7 major TEE directories covered. `fog/` sub-enclaves and `enclave-boundary/` were missed because v22's planner spent its avoid-budget gravitating toward `attest/` and `sgx/` internals. A v23 run with `--focus fog` would fill the gap.

## Cost Analysis

| Metric | v20 (single) | v22 (5 samples) | Ratio |
|---|---|---|---|
| Planner tokens | 13,767 | 66,267 | 4.8x |
| Planner wall clock | 41s | 411s | 10x |
| Candidates | 3 | 11 | 3.7x |
| Corroborated | 3 | 3 | 1.0x |
| Confirmed high-conf | 0 | 2 | — |
| Cost per candidate | 4,589 | 6,024 | 1.3x |
| Cost per corroborated | 4,589 | 22,089 | 4.8x |

Multi-sample is ~5x more expensive but produces ~4x more candidates and reaches code paths that no single run has ever touched. The cost-per-candidate is only 1.3x higher (good scaling), but cost-per-corroborated is 4.8x because many of the new candidates hit delegation boundaries where the verifier can't fully resolve.

## What a Human Auditor Should Do With This Report

**Priority 1 (30 minutes):**
1. Read `attest/ake/src/responder.rs` lines 134–201. Is the `ClientAuthRequestInput` path reachable from production clients?
2. Trace callers of `sgx/service/src/lib.rs::verify_report`. Do they inspect the report body, or just check the return code?

**Priority 2 (1 hour):**
3. Read `attest/core/src/quote.rs` lines 279–400. Does `verify()` check nonces/timestamps?
4. Read `sgx/service/src/lib.rs::report()` callers. When is `report_data=None` passed in production?

**Priority 3 (optional):**
5. Run `teecheck plan mobilecoin --samples 3 --focus fog` to fill the fog/ coverage gap.
6. Consider the 5 "contested" findings (007–011) as lower-priority follow-ups.

## Artifacts

```
04_planner/
  evidence_bundle.json     11 candidates (merged from 5 passes)
  pass-1.json .. pass-5.json   per-pass bundles
  rounds.jsonl             40 rounds (8 per pass × 5), 140KB
03_cases/                  11 case packs
04_expert/                 11 hypotheses
05_challenger/             11 challenges
06_verifier/               11 memos (3 corroborated, 5 contested, 3 inconclusive)
07_arbiter/
  findings.json            11 findings
  packets/review-*.md      11 human-readable review packets
```
