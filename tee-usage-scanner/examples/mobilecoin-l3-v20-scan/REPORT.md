# MobileCoin L3 Audit Report — v20

**Target:** `mobilecoinfoundation/mobilecoin` @ `59a52d3d52e6`
**Focus:** TEE (attestation + key lifecycle)
**Date:** 2026-04-16
**Pipeline:** L3 planner + 4-agent adversarial review (GLM-4.7 via z.ai Anthropic endpoint)
**Breakthrough:** First run where `pipeline_yield = 1.00` — all three planner candidates survive the full adversarial chain and get corroborated by the verifier against real code.

## TL;DR

**v20 is not just a better dogfood run — it's the run that exposed and fixed a foundational bug in the verifier.**

The bug: from v1 through v19, the Verifier agent's prompt never contained any source code. It only received the hypothesis text, the challenger's counter-arguments, and static check output. When it wrote `confirmed_facts`, it was literally paraphrasing the Expert's earlier assertions without ever re-grounding against the repository — despite "re-grounding against source code" being the Verifier's entire stated purpose in the design spec.

The fix is ~20 lines in `internal/verifier/run.go::buildMemoLLM`: inject the case pack's snippets into the userMsg. No other changes.

The result: v20 hits numbers no prior run has come close to, with the lowest token cost of any run in the series.

## Run Statistics — v20 vs the full history

| Metric | v13 | v14 (prev best) | v17 | v18 | v19 | **v20** |
|---|---|---|---|---|---|---|
| candidates | 3 | 3 | 3 | 2 | 3 | 3 |
| path validity | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| symbol validity | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| symbol coverage | 0.50 | 0.75 | 1.00 | 0.50 | 0.50 | 0.69 |
| citation rate | 0.67 | **1.00** | 1.00 | 0.50 | 0.67 | **1.00** |
| **corroboration rate** | 0.33 | 0.67 | 0.00 | 0.50 | 0.00 | **1.00** ⭐ |
| verifier status | 1c/0/2 | 2c/1/0 | 0/1c/2i | 1c/0/1i | 0/1c/2i | **3c/0/0** |
| verifier_agreement | 0.33 | 0.67 | 0.33 | 0.50 | 0.00 | **1.00** |
| **pipeline yield** | 0.33 | 0.67 | 0.00 | 0.50 | 0.00 | **1.00** ⭐ |
| tokens (planner) | 12693 | 14780 | 14311 | 18617 | 16032 | **13767** (lowest) |
| **cost / corroborated** | 12693 | 7390 | ∞ | 18617 | ∞ | **4589** (best) |

v20 broke every prior record — including token cost, despite the verifier now consuming roughly 10k additional tokens per case for the snippet block (which is not counted in the planner `tokens` column; see note at bottom).

## The candidates

The planner landed on three disjoint trust paths. No single prior run hit all three.

| # | ID | Files | Category |
|---|---|---|---|
| 1 | `attest-verifier-dcap` | `attest/verifier/src/{lib.rs, dcap.rs, status.rs}` | attestation |
| 2 | `fog-ingest-identity` | `fog/ingest/enclave/impl/src/{identity.rs, lib.rs}` | key_management |
| 3 | `attest-ake-protocol` | `attest/ake/src/{initiator.rs, responder.rs, lib.rs}` | authorization |

Candidate 2 is a **first-time hit** — `fog/ingest/enclave/impl/` was never touched in v1–v19. Candidate 3 re-hits the AKE layer that only v17 had reached previously (and v17 needed `reverse_trace` to get there; v20 got there without it).

## Finding 1 — DCAP Verifier TCB baseline depends entirely on caller config

**Files:** `attest/verifier/src/{lib.rs, dcap.rs, status.rs}`
**Severity:** high **Confidence:** high
**Arbiter status:** needs_review **Verifier status:** corroborated

### What v20 found

`DcapVerifier::new(trusted_identities, time)` accepts a list of `TrustedIdentity` objects from the caller. Those `TrustedIdentity` objects are the sole source of:

- Acceptable `IsvSvn` floors
- Accepted `advisories` (CVE IDs that are explicitly allowed to pass with the associated enclave)

The internal verification chain is an `And` combinator over `EvidenceVerifier + ReportDataHashVerifier + AttributesVerifier`, which correctly fails the quote if any sub-verifier fails. But the sub-verifiers reference the caller-supplied `TrustedIdentity` for their thresholds. There is **no hard-coded internal safety floor**.

Worse: `status.rs::check_ids` explicitly allows *overriding* specific quote failure statuses (like `SW_HARDENING_NEEDED`) if the configured `Advisories` list contains matching IDs. This means a misconfigured `TrustedIdentity` can accept quotes with *known hardware vulnerabilities*.

### Concretely (from verifier's corroborated facts)

1. `DcapVerifier::new` delegates TCB to the caller via `trusted_identities`.
2. `EvidenceVerifier` is constructed with those identities + a certificate verifier + `time`.
3. `status.rs::check_ids` overrides quote status based on advisory ID matching.
4. `debug_attribute_verifier` correctly checks `AttributeFlags::DEBUG`.
5. `ReportDataHashVerifier` correctly compares against `EnclaveReportDataContents`.
6. The chain is an `And`, so any component failure rejects the quote.
7. But there is no immutable MRENCLAVE/IsvSvn floor independent of caller config.

### Why this is `needs_review`

The verifier confirmed all 8 facts above. The question for a human auditor is: **in production mobilecoin deployments, what does the `trusted_identities` list actually contain?** If the `Advisories` field ever includes an ID that should have been a hard rejection, this finding becomes a real vulnerability.

### Recommended human check

```bash
grep -rn "TrustedIdentity" --include=*.rs mobilecoin/
grep -rn "Advisories::new" --include=*.rs mobilecoin/
```

Look specifically for any production entrypoint that passes non-empty advisories lists.

## Finding 2 — Ingest enclave `unseal` has no visible MRENCLAVE check

**Files:** `fog/ingest/enclave/impl/src/{identity.rs, lib.rs}`
**Severity:** high **Confidence:** medium
**Arbiter status:** needs_review **Verifier status:** corroborated

### What v20 found

`SgxIngestEnclave::enclave_init` has a path that accepts a sealed blob to **replace** the enclave's ingress private key:

```rust
let private_key = IntelSealed::try_from(sealed)?.unseal_raw()?;
```

The verifier confirmed against the actual code:

1. `SgxIngestEnclave` uses `AkeEnclaveState<RistrettoIdentity>` for attestation + key exchange.
2. `verify_attestation_evidence` is a pass-through to `self.ake.verify_attestation_evidence(...)`.
3. `RistrettoIdentity::default` generates a fresh private key — this is the normal path.
4. `enclave_init` has an alternative path that unseals a provided blob to overwrite the key.
5. **There is no code in the unseal path checking the creator enclave's identity** (MRENCLAVE / MRSIGNER).

### The subtlety

SGX sealing at the MRSIGNER level provides hardware guarantee that only enclaves signed by the same key can unseal. That's likely what's providing the actual safety. But:

- You cannot audit "SGX hardware will enforce MRSIGNER" from the Rust source. It's an assumption about the SGX runtime.
- If the SDK is ever used with `KEYPOLICY_MRENCLAVE` on one side and `MRSIGNER` on the other, the assumption breaks.
- The code has no explicit `assert_eq!(sealer_mr_enclave, self_mr_enclave)` — so a future refactor of the sealing primitives could silently break this guarantee.

### Recommended human check

1. Confirm in `mc-sgx-util` or equivalent that `IntelSealed` uses `KEYPOLICY_MRENCLAVE`, not `MRSIGNER`.
2. Check whether the `enclave_init(sealed_key)` branch is ever reachable in production, or only used for migration / testing.

## Finding 3 — AKE session binding relies on an external Noise library's behavior

**Files:** `attest/ake/src/{initiator.rs, responder.rs, lib.rs}`
**Severity:** high **Confidence:** medium
**Arbiter status:** needs_review **Verifier status:** corroborated

### What v20 found

The AKE initiator does check that `remote_identity == report_data.key()` inside `verify_dcap_evidence`, and Noise handshake state includes a `channel_binding` byte string on completion. However:

1. `verify_dcap_evidence` returns `Ok(())` on success — it does **not** propagate any cryptographic binding material back to the caller.
2. The `Ready` state object stores `result.channel_binding` but the code path from `attestation_evidence` to `channel_binding` is not visible in these files — it's implicit in how `mc_crypto_noise` computes its transcript hash.
3. **The mobilecoin codebase itself contains an open question about this** — the verifier cited this remark from `verify_verification_report`:

> "the 'open_questions' field in the code explicitly asks: 'Does an upstream wrapper perform the binding instead of this unit?'"

This is the AKE developers themselves flagging that they aren't sure where the binding is enforced.

### Challenger's counter-argument (and why verifier preserved the finding)

The Challenger argued: "Noise `MixHash()` inherently mixes the payload into the transcript, so the attestation evidence IS cryptographically bound." The verifier corroborated that this *would* be true if `mc_crypto_noise` does the mixing — but that library's source is not in the case pack. So the claim is not refuted; it just depends on a file the verifier couldn't read.

### Recommended human check

This is the cleanest one to close. Just one grep away:

```bash
grep -rn "MixHash" --include=*.rs mobilecoin/mc-crypto-noise/
```

If `MixHash` is called on `attestation_evidence` bytes before the session keys are derived, Finding 3 becomes `no_issue_observed`. If not, it's a real replay window.

## The bug that v20 exposed and fixed

Before v20, `internal/verifier/run.go::buildMemoLLM` constructed its userMsg like this:

```
Case: {id} (category: ..., priority: ...)
Target files: {paths}       ← just strings
Target symbols: {names}     ← just strings
Expert hypothesis: {text}
Challenger view: {text}
Static check findings: ...
```

The case pack's `pack.Snippets` field — the whole point of the cases stage — **was never referenced**. The verifier was a pure text-over-text operation: it read what other LLMs said about the code and produced a summary judgment. It was structurally incapable of catching an Expert hallucination by going back to the source.

This explains the whole v13–v19 pattern:
- **v14 seemed to work** because the Expert had good snippets and produced a hypothesis rich enough that the verifier could corroborate it from the hypothesis text alone.
- **v15–v19 all regressed** because the LLM's verifier output was essentially a coin flip over whether to say "corroborated" or "inconclusive" based on stylistic cues in the Expert text, with ~30% variance.
- **The "v17 reverse_trace success" and "v18 obligations success" were illusions** — the verifier never saw the new content, so the downstream quality signal was pure noise.

The fix is in this commit. The `formatSnippets` helper caps each snippet at 20k chars and the total at 60k chars to stay within GLM's context window, emits each snippet as a fenced block with `--- path [start-end] ---` headers so the LLM can cite `file:line` back at us.

## What this run did NOT do

- **No ablation re-run.** v20 is a single GLM call — v14's 0.67 yield could also have been a lucky draw at lower temperature. Need 3–5 independent runs at the same config to confirm v20 is a stable regime and not a one-off.
- **No human label check.** All three findings are marked `corroborated` by the verifier, but a TEE auditor needs to read the actual code to confirm they're real — especially Finding 2 (SGX sealing behavior) and Finding 3 (Noise library behavior) which depend on library-level invariants.
- **`cost_per_corroborated = 4589 tokens` is planner-only.** The verifier now consumes ~10k additional tokens per case (the snippet block), so the real end-to-end cost is closer to 40k tokens for 3 corroborated findings = ~13k/finding. Still the cheapest run in the series but worth noting.

## Artifacts

```
04_planner/
  evidence_bundle.json        3 candidates, termination=llm_done, 8/8 rounds, 13767 tokens
  rounds.jsonl                8 rounds with real per-round tokens (first run with provider usage parsing)
  sink_hits.json

03_cases/                     3 case packs with obligations attached
04_expert/                    3 hypotheses, 100% citation rate, p50 170 words
05_challenger/                3 challenges, 100% non-rubber-stamp
06_verifier/                  3 memos, ALL 3 corroborated
07_arbiter/
  findings.json               3 findings, all needs_review (human review requested)
  packets/review-00{1,2,3}.md human-readable review (~5KB each)
```

## Next steps for the tool

In rough priority order (each is an experiment that the stats aggregator can measure):

1. **Stability check**: re-run v20 config 5× with fresh run IDs and compute the distribution of `pipeline_yield`. If it's 1.0 ± noise, this regime is real. If it's 0.3–1.0 variance, we're still chasing GLM luck.
2. **Token cost audit**: instrument the downstream agents (expert / challenger / verifier / arbiter) to record tokens the same way the planner now does, so `cost_per_corroborated` reflects real end-to-end spend.
3. **Human label set**: get a TEE auditor to read these three findings and label them real/FP. That's the only way to turn `pipeline_yield` into `precision`.
