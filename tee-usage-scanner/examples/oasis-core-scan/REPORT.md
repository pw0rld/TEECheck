# TEECheck Audit Report: oasis-core

**Repository:** git@github.com:oasisprotocol/oasis-core.git  
**Commit:** e650c8ee0c1aeeb58aceb0be264dfb412e57a0f4  
**Run ID:** oasis-core-l3

## Executive Summary

This audit evaluated the Trusted Execution Environment (TEE) implementation within the `oasis-core` runtime, specifically focusing on attestation verification, trust boundary enforcement, and authorization logic. The review analyzed six candidates across critical security domains, including SGX quote verification, IAS AVR handling, and dispatcher entry points.

The audit identified **one high-severity confirmed issue** regarding incomplete cryptographic verification in the Intel Attestation Service (IAS) integration. The `verify` function in `runtime/src/common/sgx/ias.rs` validates the IAS signature and metadata but fails to verify the internal integrity of the SGX Quote body or enforce enclave identity (MRENCLAVE/MRSIGNER), potentially allowing unauthorized enclaves to be trusted. Additionally, three medium-severity issues were flagged requiring human review, primarily concerning the sufficiency of trust boundary revalidation and the location of authorization logic. One finding regarding quote replay protection was determined to be a false positive, as the implementation correctly enforces monotonicity.

## Findings

### 1. Incomplete Quote Verification in IAS Handler
**ID:** oasis-core@e650c8e:tee:attestation:004  
**Status:** `confirmed_candidate`  
**Severity:** High  
**Confidence:** High  
**Files:** `runtime/src/common/sgx/ias.rs`

**Core Observation:**
The attestation verification logic in `ias.rs` validates the wrapper (Attestation Verification Report or AVR) and metadata but fails to verify the cryptographic integrity of the SGX Quote body itself or enforce enclave identity (MRENCLAVE/MRSIGNER). This creates a security gap where validly signed EPID quotes from unauthorized enclaves could be accepted.

**Evidence:**
The `verify` function performs the following checks:
- Calls `validate_avr_signature` to ensure the AVR was signed by Intel.
- Checks `isvEnclaveQuoteStatus`, timestamp freshness, and EPID GID blacklist.
- Decodes `isvEnclaveQuoteBody` into a `QuoteBody` struct.

However, it omits the critical step of verifying the Quote body's internal signature or validating the enclave's identity against a policy.
```rust
// runtime/src/common/sgx/ias.rs:247-306
pub fn verify(avr: &AVR, policy: &QuotePolicy) -> Result<VerifiedQuote> {
    // ...
    // Verify IAS signature.
    validate_avr_signature(
        // ...
    )?;

    // Decode quote body
    let quote_body = QuoteBody::decode(&BASE64_STANDARD.decode(&avr.isv_enclave_quote_body)?)?;

    // Check GID and debug flags
    if policy.gid_blacklist.contains(&quote_body.header.gid) {
        return Err(Error::QuoteGidBlacklisted);
    }
    // ...
}
```
Note that `QuoteBody::decode` is purely a deserialization step. There is no call to a method like `quote_body.verify()` or a check comparing `quote_body.report_body.mrenclave` against an expected value.

**Recommended Follow-up:**
Implement cryptographic verification of the `QuoteBody` and enforce `MRENCLAVE`/`MRSIGNER` validation within the verification path. The current implementation provides a false sense of security by validating the transport layer (IAS) but failing to validate the payload (Quote) integrity or identity.

---

### 2. Missing Caller Binding in Policy Authorization
**ID:** oasis-core@e650c8e:tee:authorization:006  
**Status:** `needs_review`  
**Severity:** High  
**Confidence:** Medium  
**Files:** `runtime/src/policy.rs`

**Core Observation:**
The target symbol `Policy::check_allowed` is missing from the provided source code, preventing the verification of authorization and caller binding obligations. The file contains a `PolicyVerifier` struct focused on consensus-layer verification (e.g., `verify_quote_policy`), but lacks the specific runtime authorization logic required to verify caller binding.

**Evidence:**
- The provided code snippet defines `PolicyVerifier` but does not contain `Policy::check_allowed`.
- `PolicyVerifier` focuses on consensus layer verification rather than runtime access control.
- The code focuses on consistency checks against on-chain data, not runtime caller authorization.

**Recommended Follow-up:**
Review the call sites of `PolicyVerifier` and the broader runtime module to locate where `check_allowed` or equivalent caller binding logic is implemented. Ensure that the trust boundary is revalidated before sensitive operations.

---

### 3. Trust Boundary Revalidation in AttestationHandler
**ID:** oasis-core@e650c8e:tee:boundary:002  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `runtime/src/attestation.rs`

**Core Observation:**
The `AttestationHandler` lacks explicit caller binding (e.g., session ID validation) within its methods. While the handler validates the cryptographic content of quotes and reports, it does not appear to verify that the request originates from a specific, authorized host session before processing sensitive attestation data. The Challenger argues this is redundant due to the `Host` trait architecture, but the Expert maintains this violates defense-in-depth principles.

**Evidence:**
- The `handle` function dispatches requests based on `Body` type without inspecting caller metadata.
- The `report_init` and `set_quote` methods directly invoke `self.identity.init_report()` and `self.identity.set_quote()` without intermediate authorization checks.
- The `set_quote` method retrieves the `node_id` via `self.host.identity().await?`, but this is used as a payload parameter for signing rather than for authorizing the caller of the function itself.

**Recommended Follow-up:**
Evaluate if the `Host` trait implementation and RPC transport layer strictly guarantee that *only* the authorized host process can invoke `Handler::handle`. Determine if the lack of per-request caller validation inside the enclave is acceptable or if explicit revalidation (Defense in Depth) is required.

---

### 4. Potential Replay Protection Gap in Quote Verification
**ID:** oasis-core@e650c8e:tee:attestation:003  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `runtime/src/common/sgx/pcs/quote.rs`

**Core Observation:**
The verification of SGX quotes in `QuoteBundle::verify` raises a concern regarding replay protection. The function validates the expiration of TCB certificates and info using a provided timestamp `ts`, but the visible code does not demonstrate validation of the quote's generation time (freshness). The evidence was truncated, preventing a definitive conclusion on whether freshness is enforced by the caller or omitted entirely.

**Evidence:**
- The `ts` parameter is present and used for TCB-related validity checks. No explicit quote timestamp validation is visible in lines 1-80.
- The code snippet ends at line 80, missing the invocation of `quote.verify(...)` and the return statement.
- It is unclear if the caller of `QuoteBundle::verify` performs the necessary nonce comparison to ensure replay resistance.

**Recommended Follow-up:**
Review the complete implementation of `QuoteBundle::verify` and its callers. Ensure that either the quote verification logic or the calling code explicitly enforces freshness guarantees (e.g., via nonce validation) to prevent replay attacks.

---

### 5. Missing Trust Boundary Revalidation in Dispatcher
**ID:** oasis-core@e650c8e:tee:boundary:005  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `runtime/src/dispatcher.rs`

**Core Observation:**
The provided code snippet for `runtime/src/dispatcher.rs` (lines 1-80) does not contain the implementation of the target function `Dispatcher::dispatch_txn`. Consequently, it is impossible to confirm if critical security obligations (trust boundary revalidation, authorization and caller binding) are met based solely on the provided snippet. However, tool hits referenced by the Challenger suggest verification logic exists later in the file (e.g., lines 617, 619).

**Evidence:**
- The target function `Dispatcher::dispatch_txn` is not present in the provided snippet (lines 1-80).
- The snippet only includes imports, constants, and trait definitions.
- The Challenger asserts that tool hits indicate the existence of verification logic (e.g., `consensus_verifier.verify`, `verify_quote_policy`) at lines 505, 617, 619, 777, 953, 960, 988, and 996.

**Recommended Follow-up:**
Locate and review the implementation of `Dispatcher::dispatch_txn` (specifically around lines 600+) to verify that the `PolicyVerifier` and `Verifier` imports are actually used to enforce trust boundary revalidation and secure failure behavior for untrusted host data.

---

### 6. Replay Protection in Identity::set_quote
**ID:** oasis-core@e650c8e:tee:attestation:001  
**Status:** `no_issue_observed`  
**Severity:** Low  
**Confidence:** High  
**Files:** `runtime/src/identity.rs`

**Core Observation:**
The Expert hypothesized that the function enables replay attacks by accepting stale quotes when returning `Ok(verified_quote)` early. The Arbiter found this to be incorrect. The implementation correctly rejects stale quotes by enforcing monotonic timestamp updates and preserves the existing state.

**Evidence:**
- **State Preservation:** When `existing_timestamp > verified_quote.timestamp`, the function returns early. Critically, `inner.quote` and `inner.quote_timestamp` are **not** updated.
- **Monotonicity:** The check `existing_timestamp > verified_quote.timestamp` ensures that the node's attestation state only moves forward in time.
- **Return Value:** The function returns `Ok(verified_quote)`, where `verified_quote` is the *input* quote that was just determined to be stale. It is **not** the quote currently stored in `inner.quote`.

**Recommended Follow-up:**
None. The logic is sound and correctly prioritizes the most recent attestation evidence.

---

## Coverage

### Audited Directories/Crates
The review focused on the following paths within the `oasis-core` repository:
- `runtime/src/identity.rs`
- `runtime/src/attestation.rs`
- `runtime/src/common/sgx/pcs/quote.rs`
- `runtime/src/common/sgx/ias.rs`
- `runtime/src/dispatcher.rs`
- `runtime/src/policy.rs`

### Coverage Notes
- **Attestation:** Coverage included SGX quote verification (both PCS and IAS paths) and identity management.
- **Boundaries:** FFI and trust boundaries were reviewed at the dispatcher and attestation handler levels.
- **Authorization:** Policy verification and runtime access control logic were examined.
- **Limitations:** Some findings (e.g., Packet 3 and Packet 5) were affected by truncated code snippets or missing function implementations in the provided context, necessitating the "needs_review" status.

## Next Steps

1.  **Address High-Severity Issue:** Immediately remediate the incomplete quote verification in `runtime/src/common/sgx/ias.rs` (Finding #1) to ensure MRENCLAVE/MRSIGNER validation occurs.
2.  **Resolve "Needs Review" Items:**
    *   Verify the implementation of `Dispatcher::dispatch_txn` in `runtime/src/dispatcher.rs` to confirm boundary checks exist (Finding #5).
    *   Locate or implement `Policy::check_allowed` or equivalent caller binding logic (Finding #6).
    *   Determine if architectural trust assumptions in `AttestationHandler` are sufficient or if explicit caller binding is required (Finding #2).
    *   Confirm replay protection mechanisms in `QuoteBundle::verify` (Finding #3).
3.  **Documentation:** Update documentation to clarify trust assumptions regarding the `Host` trait and caller responsibilities if explicit checks are deemed unnecessary.