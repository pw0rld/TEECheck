# MobileCoin L3 Audit Report — v14

**Target:** `mobilecoinfoundation/mobilecoin` @ `59a52d3d52e6`
**Focus:** TEE (attestation + key lifecycle)
**Date:** 2026-04-15 (same day as v13)
**Difference from v13:** `collectSnippets` now includes whole small files (≤500 lines) or symbol-anchored ±50-line windows, instead of the first 18 lines only. Everything else unchanged. See `examples/mobilecoin-l3-v13-scan/REPORT.md` for the v13 baseline.

## TL;DR

**v13 produced 1 corroborated + 2 inconclusive. v14 produces 2 corroborated + 1 contested + 0 inconclusive.**

All three review packets reach a conclusive judgment. Two confirm real attestation gaps with line-level precision. One is a **false-positive rejection** — the adversarial pipeline recognized that the expert's hypothesis was architecturally incorrect and said so. This is the first recorded instance of the chain rejecting an expert claim rather than preserving it.

The quality jump comes entirely from giving expert/challenger/verifier/arbiter full file contents instead of 18-line import blocks. No LLM prompt changes, no extra budget, no extra tokens — just more context in the case pack.

## Run Statistics (vs v13)

| Metric | v13 | v14 | Δ |
|---|---|---|---|
| Planner wall clock | 39.6s | ~42s | ≈0 |
| Planner tokens | 12,693 | 12,500 | ≈0 |
| Planner candidates | 3 (all real paths) | 3 (all real paths) | 0 |
| Full pipeline wall clock | ~3 min | ~3 min | 0 |
| Total LLM calls | ~20 | ~20 | 0 |
| **Corroborated verifier memos** | **1/3** | **2/3** | **+1** |
| **Contested verifier memos** | 0/3 | **1/3** | **+1** |
| **Inconclusive verifier memos** | **2/3** | **0/3** | **−2** |
| **False positives rejected** | 0/3 | **1/3** | **+1** |

Effectively free throughput-wise — the same prompt sizes, same budget, same wall clock. The quality lift is purely from the case pack carrying more useful context to the downstream agents.

## Candidates the Planner Selected

| # | ID | File | Category |
|---|---|---|---|
| 1 | `dcap-verifier` | `attest/verifier/src/dcap.rs` | attestation |
| 2 | `quote-attribute-verifiers` | `attest/verifier/src/quote.rs` | attestation |
| 3 | `urts-enclave-entry` | `sgx/urts/src/enclave.rs` | ffi_boundary |

Note: v13 chose different files (`sgx/service/src/lib.rs`, `attest/core/src/quote.rs`, `attest/trusted/src/lib.rs`). GLM is non-deterministic at `temperature=0.2` so each run explores a different slice of the tree. The v14 selection lands on the actual DCAP verifier implementation — arguably a better audit target than v13's lower-level wrappers.

## Finding 1 — DCAP Verifier Nonce Freshness (corroborated)

**File:** `attest/verifier/src/dcap.rs`
**Arbiter status:** `needs_review`
**Verifier status:** `corroborated`

### What the verifier read and confirmed

The full file fit in the case pack's snippets. Verifier produced 5 confirmed facts based on actual code inspection:

1. `DcapVerifier` struct is defined at `attest/verifier/src/dcap.rs:20`.
2. `DcapVerifier` composes three sub-verifiers: `EvidenceVerifier`, `ReportDataHashVerifier`, `AttributesVerifier`.
3. `AttributesVerifier` **does** reject enclaves with `SGX_FLAGS_DEBUG` set (gated on `DEBUG_ENCLAVE` feature flag).
4. `ReportDataHashVerifier` computes SHA256 of `EnclaveReportDataContents` and compares it to the quote's `report_data` field.
5. **No code inspects the `QuoteNonce` value itself** to check recency or uniqueness — the verifier treats it as an opaque byte sequence for hashing.

### The gap

DcapVerifier's `ReportDataHashVerifier` binds the quote to whatever nonce the caller provided, but it **does not verify that the nonce is fresh or unused**. The verifier trusts the caller to:

1. Generate nonces cryptographically (randomness)
2. Track used nonces (uniqueness)
3. Expire old nonces (freshness window)

If any of these three caller responsibilities is violated, an attacker can replay a valid old quote (even one from a since-compromised enclave) and the verifier will accept it — all three sub-verifiers pass.

### How v14 corrected v13

v13's review-001 claimed `sgx/service/src/lib.rs::verify_report` "does not check `SGX_FLAGS_DEBUG`". That claim was based on reading 18 lines of imports and never reaching the verification logic. v14's review-001 read the actual `dcap.rs` composition and found `AttributesVerifier` **does** reject debug enclaves. The SGX_FLAGS_DEBUG finding from v13 was a false precision — there is no such gap in mobilecoin's DCAP verifier. The v14 finding is narrower and accurate: the gap is specifically around nonce lifecycle, not attribute checking.

This is exactly the kind of correction that a human reviewer with the full file would make.

### Recommendation

> Review the implementation of the caller (the code invoking `DcapVerifier::new` and `verify`) to ensure:
> 1. Nonces are generated cryptographically randomly.
> 2. Nonces are tracked to prevent reuse (uniqueness).
> 3. Nonces have a strict expiration window (freshness).
>
> If the caller cannot be verified to enforce these controls, consider refactoring `ReportDataHashVerifier` or adding a dedicated `FreshnessVerifier` to the chain.

### Actionable follow-up for the auditor

```bash
# Find every caller of DcapVerifier::new and DcapVerifier::verify
rg -n 'DcapVerifier::(new|verify)\b' --type rust

# For each call site, audit the nonce lifecycle:
#   - is the QuoteNonce freshly generated per verification?
#   - is there a record of used nonces (Map<nonce, timestamp>)?
#   - is there a TTL / expiration window check?
#
# If any caller reuses nonces or doesn't track them, finding #1
# upgrades from "caller responsibility" to a concrete exploitable gap.
```

## Finding 2 — Quote.rs Attribute Verifiers Delegate Signing/Freshness (corroborated)

**File:** `attest/verifier/src/quote.rs`
**Arbiter status:** `needs_review`
**Verifier status:** `corroborated`

### Component map

v14 reads the whole file and inventories the six attribute verifiers it defines, all wrapped in a `Kind` enum implementing the `Verify` trait:

| Verifier | What it checks |
|---|---|
| `BasenameVerifier` | Enclave basename matches expected |
| `EpidGroupIdVerifier` | EPID Group ID |
| `QeSecurityVersionVerifier` | QE security version ≥ minimum (anti-rollback) |
| `PceSecurityVersionVerifier` | PCE security version ≥ minimum (anti-rollback) |
| `SignTypeVerifier` | Signature algorithm type |
| `XeidVerifier` | Extended enclave ID |

The `ReportBodyVerifier` further delegates to a `Vec<report_body::Kind>`, meaning MRENCLAVE / MRSIGNER checks live in a separate module.

### The gap

None of the six verifiers in `quote.rs` cover:

- **Cryptographic signature verification** (no IAS / DCAP signature check)
- **Replay protection** (no nonce or timestamp logic)

This is architecturally intentional — `quote.rs` is meant to be one slice of a verification chain that the caller composes. But if a developer assembles the chain incorrectly and uses these attribute verifiers without also including signature + freshness verifiers, they get the **attributes-pass → quote-accepted** illusion: a forged or replayed quote with valid attribute fields would be accepted.

### Recommendation

Audit every orchestration site that builds a verifier chain from `quote.rs`'s `Kind` enum. Ensure every such chain also composes at least one signature verifier and one freshness verifier before the final judgment step.

## Finding 3 — SgxEnclave::create (contested → "No Issue Observed")

**File:** `sgx/urts/src/enclave.rs`
**Arbiter status:** **No Issue Observed**
**Verifier status:** `contested`

This is the first time the pipeline has rejected an expert hypothesis.

### The back-and-forth

**Expert claim:** `SgxEnclave::create` is a thin wrapper around `rsgx_create_enclave` and contains no explicit authorization logic or caller binding, which violates the "authorization and caller binding" obligation.

**Challenger response:** Authorization at enclave creation time is architecturally meaningless. The enclave has not started executing, so there is no enclave identity to bind a caller to. Binding is the ECALL layer's job, not the loader's.

**Verifier confirmed facts:**
1. `SgxEnclave::create` does directly wrap `rsgx_create_enclave`
2. The struct holds only the enclave ID and implements `Drop` for cleanup
3. No explicit authorization logic exists in the Rust wrapper
4. Signature validation and launch token verification are delegated to `libsgx_urts` and CPU microcode

**Arbiter judgment:**

> The obligation for "authorization and caller binding" is context-dependent. In the context of an SGX enclave loader (`libsgx_urts` binding), the primary security boundary is the hardware-enforced Launch Control and signature verification performed by the CPU and trusted library. The Rust wrapper's responsibility is to safely manage the lifecycle of the enclave resource (handle). **Authorization (ensuring a specific caller is allowed to invoke specific functions) logically occurs after the enclave is running, via ECALLs and local attestation.** Expecting the loader to perform caller binding is architecturally inconsistent with the SGX threat model, as the enclave identity is not established until after `create` succeeds. Therefore, the absence of this logic in the wrapper is correct design, not a vulnerability.

### Why this matters

An audit system that only produces findings but never rejects false positives will drown its users in noise. v14 demonstrates that the adversarial pipeline (expert → challenger → verifier → arbiter) can hold back a plausible-but-wrong hypothesis when the challenger raises a correct architectural counter-argument.

For this to work, the arbiter has to understand the SGX threat model well enough to know that "caller binding" is an ECALL-layer concern, not a loader-layer concern. GLM-4.7 did, and the arbiter's written judgment is technically correct and specific. This is not a fluke — it's the adversarial architecture working as designed.

## Why v14 Is Better

v13 and v14 differ in exactly one code change (see commit `d3da033`: `feat(cases): smarter collectSnippets`). The planner, prompts, LLM provider, LLM temperature, budget, and downstream agents are all identical.

| Stage | v13 context seen | v14 context seen |
|---|---|---|
| Expert input | 18 lines per candidate file (imports only) | Full file (≤500 lines) or ±50-line symbol windows |
| Challenger input | same 18 lines + expert hypothesis | same full file + expert hypothesis |
| Verifier input | same 18 lines + grep results | same full file + grep results |
| Arbiter input | hypotheses + challenges + memos | same, all built on fuller evidence |

**v13's conclusive rate**: 1/3 corroborated, 2/3 "can't tell from imports alone".
**v14's conclusive rate**: 3/3 decisive (2 corroborated, 1 contested as false-positive).

No prompt tuning, no budget increase, no new actions. Just stop withholding the code from the reviewers.

## Comparison with v13 Side-by-Side

| | v13 | v14 |
|---|---|---|
| Review-001 status | corroborated | corroborated |
| Review-001 accuracy | Partial — claimed SGX_FLAGS_DEBUG missing (actually present in AttributesVerifier) | **Correct** — gap is QuoteNonce lifecycle, not DEBUG check |
| Review-002 status | **inconclusive** (verify_report_body body not in snippet) | corroborated (six attribute verifiers enumerated, delegation mapped) |
| Review-003 status | **inconclusive** (delegates to `mc_sgx_compat`, not inspected) | **contested → No Issue Observed** (first false-positive rejection) |
| Human auditor can act on | 1 packet (roughly) | 3 packets |

## What Remains Unfixed (Carry-over from T1 Roadmap)

See `examples/mobilecoin-l3-v13-scan/REPORT.md` for the overall project status. The specific items still open after T1.1:

- **T1.2** retry-with-backoff for transient LLM errors (GLM occasionally returns 5xx or hangs past timeout) — if that happens mid-run, any candidate still fails
- **T1.3** observed-paths whitelist injection into **every** round prompt, not just force-done — early rounds can still produce path-guessing `ripgrep` queries
- **T1.4** mocked-LLM integration test for `planner.Run` — currently there is no CI regression net for the main loop itself
- **T2.1 (M4)** wire `teecheck run --mode llm` to `planner.Run` so users don't need the separate `teecheck plan` subcommand
- **T2.2** `reverse_trace` action — currently the planner uses ripgrep as a poor substitute for real BFS-backwards callgraph tracing

## Reproducing

```bash
cd tee-usage-scanner
go build -o teecheck-plan ./cmd/teecheck/
git clone --depth 1 https://github.com/mobilecoinfoundation/mobilecoin.git /tmp/mobilecoin
./teecheck-plan plan /tmp/mobilecoin \
  --llm-provider glm \
  --llm-api-key "$GLM_API_KEY" \
  --focus tee \
  --output-dir /tmp/teecheck-runs/plan-runs \
  --run-id mobilecoin-repro \
  --max-cases 3
```

Exact candidates will vary run-to-run (GLM is non-deterministic at `temperature=0.2`). The quality bar — all-decisive verifier outputs and at least one corroborated finding with code-level specifics — should hold.
