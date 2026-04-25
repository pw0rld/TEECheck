# MobileCoin L3 Audit Report — v17

**Target:** `mobilecoinfoundation/mobilecoin` @ `59a52d3d52e6`
**Focus:** TEE (attestation + key lifecycle)
**Date:** 2026-04-15
**What's new in v17:** First run with the `reverse_trace` action (T2.2). The LLM autonomously traced backward from a low-level attestation wrapper into the AKE (Authenticated Key Exchange) protocol layer — a code path no prior dogfood run (v1–v16) ever reached.

## TL;DR

**v17 is the first time the planner autonomously pivoted from "low-level SGX wrapper" into "high-level trust-decision code".** It did so in one action call, not six ripgreps.

- Round 6: LLM called `reverse_trace(file="sgx/service/src/lib.rs", symbol="verify_report", depth=2)`.
- Result: 15 caller sites, including `attest/ake/src/initiator.rs:258 in verify_dcap_evidence` and `attest/ake/src/initiator.rs:287 in verify_verification_report`.
- Round 7: LLM read `initiator.rs:250-290` and immediately saw two adjacent functions using **two different caller-binding styles** in the same file — exactly the kind of inconsistency a human auditor would flag.

All three review packets reached `needs_review` with medium confidence. One is a real code-consistency finding in `attest/ake/src/initiator.rs` that would be invisible to any heuristic picker and to earlier L3 runs that only ripgrepped for sink symbols.

## Run Statistics (vs v14)

| Metric | v14 | v17 | Δ |
|---|---|---|---|
| Planner wall clock | ~42s | **42.9s** | ≈0 |
| Planner tokens | 12,500 | **14,311** | +1,811 |
| Planner rounds used | 8/8 | **8/8** | 0 |
| Planner candidates | 3 (all real paths) | **3 (all real paths)** | 0 |
| Termination reason | llm_done | **llm_done** | same |
| `reverse_trace` calls | 0 | **1** | **+1** |
| Files first-touched (never in v1–v16) | — | `attest/ake/src/initiator.rs`, `attest/ake/src/responder.rs` | **+2** |
| Corroborated / contested / needs_review | 2 / 1 / 0 | 0 / 0 / **3** | — |

The +1,811 token cost is the reverse_trace observation (15 callers × ~120 tokens each) plus the enclosing-function analysis. Cheap compared to six extra `ripgrep` + `tree_sitter_outline` round-trips.

## Candidates the Planner Selected

| # | ID | File | Category |
|---|---|---|---|
| 1 | `tee-attestation-sgx-service` | `sgx/service/src/lib.rs` | attestation |
| 2 | `tee-attestation-ake-initiator` | `attest/ake/src/initiator.rs` | authorization |
| 3 | `tee-attestation-ake-responder` | `attest/ake/src/responder.rs` | authorization |

Candidates 2 and 3 were reached **only** via `reverse_trace`. Without it, the LLM would have stopped at candidate 1 (the low-level SGX wrapper) the way every prior run did.

## The Planner's Trace (abbreviated)

```
round 1  sink_catalog_lookup scope="*"
round 2  ripgrep "verify_report" globs=["*.rs"]
round 3  tree_sitter_outline sgx/service/src/lib.rs
round 4  read_file sgx/service/src/lib.rs (lines 1-120)
round 5  sink_catalog_lookup scope="attestation"
round 6  reverse_trace sgx/service/src/lib.rs verify_report depth=2
         → verify_report (target in sgx/service/src/lib.rs)
             - attest/trusted/src/lib.rs:40 in verify
             - attest/ake/src/initiator.rs:258 in verify_dcap_evidence
             - attest/ake/src/initiator.rs:287 in verify_verification_report
             - attest/ake/src/responder.rs:164 in try_next
             - attest/verifier/src/dcap.rs:204 in report_data_hash_verifier_succeeds
             - attest/verifier/src/dcap.rs:233 in report_data_hash_verifier_fails
             - ... (9 more callers)
round 7  read_file attest/ake/src/initiator.rs (lines 250-300)
round 8  done (3 candidates)
```

Round 6 is the one that matters. Every prior dogfood run got stuck ripgrepping sink symbols and never walked *up* the call graph. v17 is the first where the LLM's own judgment ("I should see where `verify_report` is actually *used*") drove it into the code where real trust decisions live.

## Finding 2 — `verify_dcap_evidence` caller-binding inconsistency (needs_review)

**File:** `attest/ake/src/initiator.rs`
**Arbiter status:** `needs_review`
**Severity:** medium
**Confidence:** medium

### What the planner read

Lines 250–290 of `attest/ake/src/initiator.rs`, spanning two adjacent functions: `verify_dcap_evidence` and `verify_verification_report`.

### The observation

Two functions sitting next to each other in the same file use **two different styles** to bind the remote identity to the attestation result:

**`verify_dcap_evidence`** (line 251):
```rust
if remote_identity.map_bytes(|bytes| bytes != report_data.key().to_bytes().as_slice()) {
    return Err(Error::BadRemoteIdentity);
}
let verifier = DcapVerifier::new(identities, time, report_data);
// ...
let verification_output = verifier.verify(&evidence);
```

**`verify_verification_report`** (line 283):
```rust
let _report_data = verifier
    .report_data(&remote_identity.map_bytes(|bytes| {
        ReportDataMask::try_from(bytes).map_err(|_| Error::BadRemoteIdentity)
    })?)
    .verify(report)?;
```

- `verify_dcap_evidence` does a **manual pre-check** that `remote_identity` matches `report_data` *before* creating the `DcapVerifier`, then trusts the verifier to not re-check.
- `verify_verification_report` **delegates** the check to the verifier instance via `.report_data(...)`.

### Why this matters

Two risks:

1. **False negative risk.** `remote_identity.map_bytes(...)` in the manual check (line 251) depends on what `map_bytes` actually returns. If it returns a boolean predicate, the check is sound. If it returns a `Result` / `Option` that auto-derefs to a truthy value regardless of the inner comparison, the `if` block always fires or never fires — either way the check is broken.
2. **Inconsistency risk.** Two adjacent functions in the same file using different binding styles is the kind of drift that accumulates over years of refactors. One of them is probably wrong, and you can't tell which by reading just this file.

### Recommendation

> Verify the return type of `KexPublic::map_bytes` in the trait definition. If it returns `bool`, the manual check at line 251 is sound but redundant (the `DcapVerifier` already enforces binding internally via `report_data`). If it returns something else, the `if` condition is misusing the API and should be rewritten. Either way, standardize the two functions to use the same pattern — delegating to `.report_data()` on the verifier is the safer choice because it keeps binding logic inside the verification library rather than in every caller.

**Caveat:** This is flagged as `needs_review` rather than `corroborated` because the verifier was not given the `KexPublic` trait definition in the case pack — it reasoned about the risk but couldn't resolve it definitively. A follow-up reverse-trace pass targeting `map_bytes` would close this.

## Findings 1 and 3 (summary)

- **Finding 1** (`sgx/service/src/lib.rs::verify_report`): Low-level wrapper does not enforce MRENCLAVE / nonce policy. Challenger correctly notes this is standard wrapper design where policy belongs to the caller; Expert correctly notes the absence. Arbiter leaves as `needs_review` pending reverse-trace of all callers to confirm every caller path does enforce identity.
- **Finding 3** (`attest/ake/src/responder.rs::try_next`): Server-side DCAP verification may not bind the Noise session binding to the verified identity. Arbiter flags `ClientAuthRequestInput` flow (lines 189–201) which appears to skip attestation entirely — the existence of an unauthenticated mode is itself worth auditing. `needs_review`.

## What Changed Between v14 and v17

| Change | Effect |
|---|---|
| `reverse_trace` action added (T2.2) | LLM can walk backward through `.rs` files in one action |
| `actionArgSchemas` entry for `reverse_trace` | LLM got the arg schema right on the first try (no hallucinated param names) |
| Observed-paths whitelist now covers every round (T1.3) | No hallucinated paths in v17 candidates — all 3 files exist on disk |

No prompt changes beyond the new action entry. No budget changes. The v17 quality lift is entirely from giving the LLM a new action that matches the shape of the question it already wanted to ask.

## What's Still Missing

- **Symbol-in-file hallucination.** The bundle claims `try_next` lives in `responder.rs`, but the verifier would need to grep to confirm it's in that exact file. Currently the verifier catches this post-hoc; prevention at planner time is future work.
- **Deeper reverse-trace.** v17 used `depth=2`. For the `map_bytes` question above, `depth=3` would have pulled in the trait definition. The LLM didn't try it, probably because it was already on round 7/8.
- **Cross-file obligation checking.** The v17 finding 1 gap ("caller must enforce MRENCLAVE") would benefit from an action that enumerates all callers and checks each for the required obligation. No such action exists yet.

## Artifacts

All under `04_planner/` and `07_arbiter/` in the run dir:

- `04_planner/evidence_bundle.json` — 3 candidates, termination `llm_done`
- `04_planner/rounds.jsonl` — 8 rounds, round 6 contains the full `reverse_trace` observation
- `07_arbiter/findings.json` — 3 findings, all `needs_review`
- `07_arbiter/packets/review-00{1,2,3}.md` — human-readable review packets
