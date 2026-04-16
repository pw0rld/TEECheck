# TEECheck Audit Report: phala-blockchain

**Repository:** `git@github.com:Phala-Network/phala-blockchain.git`  
**Commit:** `654b1b69995b559692bcd2d8a77c3940dd308ce7`  
**Run ID:** `phala-blockchain-l3`  
**Date:** 2023-10-27

---

## Executive Summary

This audit evaluated the Trusted Execution Environment (TEE) implementation within the Phala Blockchain codebase, specifically focusing on attestation validation, key management, and trust boundary enforcement. The review identified critical security gaps in the attestation verification logic, including the potential acceptance of debug-mode enclaves, incomplete validation of IAS report content (freshness and security advisories), and a governance-controlled bypass mechanism for attestation entirely. Additionally, the key management module was found to utilize unsafe error handling that could lead to denial-of-service (DoS) conditions via storage-based attacks.

While the cryptographic primitives for signature verification appear correctly implemented, the surrounding logic enforcing security policies (e.g., debug flags, hardware compromise status) is either missing, skipped, or delegated without clear visibility. The most critical findings require immediate remediation to ensure the TEE enforces production-grade security guarantees and handles untrusted inputs gracefully.

**Recommended Actions:**
1.  **Immediate:** Remove or harden the `opt_out_enabled` attestation bypass in production.
2.  **High Priority:** Implement verification for `attributes` (Debug flag) and `misc_select` in the DCAP flow.
3.  **High Priority:** Refactor `MasterKey` unsealing logic to prevent panics on corrupted storage.
4.  **High Priority:** Add freshness and advisory ID checks to IAS report verification.

---

## Detailed Findings

### 1. Governance-Controlled Attestation Bypass
**ID:** `phala-blockchain@654b1b6:tee:attestation:001`  
**Status:** `needs_review` | **Severity:** `high` | **Confidence:** `high`  
**Files:** `pallets/phala/src/utils/attestation.rs`, `pallets/phala/src/utils/attestation_legacy.rs`

**Core Observation:**
The attestation validation module contains a functional bypass (`opt_out_enabled`) that allows the system to return a successful `ConfidentialReport` without performing any cryptographic attestation verification. This effectively allows unverified workers to participate if the governance parameter is toggled.

**Evidence:**
In `pallets/phala/src/utils/attestation.rs` (lines 112-149), the `validate` function handles the `None` case for attestation as follows:
```rust
None if opt_out_enabled => Ok(ConfidentialReport {
    provider: None,
    runtime_hash: Vec::new(),
    confidence_level: 128u8,
}),
```
This path skips `validate_ias_report` and `validate_dcap`, bypassing signature verification, quote status validation, and freshness checks. It returns an empty `runtime_hash`, bypassing the `pruntime_allowlist`.

**Recommended Follow-up:**
1.  Verify that `opt_out_enabled` is strictly disabled in all production runtime configurations.
2.  Audit the calling code to ensure `confidence_level: 128` triggers a fail-safe or "untrusted" state and does not grant full permissions.

---

### 2. Incomplete IAS Attestation Verification
**ID:** `phala-blockchain@654b1b6:tee:attestation:002`  
**Status:** `confirmed_candidate` | **Severity:** `high` | **Confidence:** `high`  
**Files:** `crates/sgx-attestation/src/ias.rs`, `crates/sgx-attestation/src/ias/report.rs`

**Core Observation:**
The `verify_signature` function in `crates/sgx-attestation/src/ias.rs` validates the cryptographic signature and certificate chain but fails to validate the *content* of the report. It does not enforce freshness (timestamp), check for hardware advisories (`advisory_ids`), or verify enclave identity (`mr_enclave`, `mr_signer`) against an allowlist.

**Evidence:**
The function `verify_signature` (lines 94-119) returns `Ok(())` immediately after signature validation:
```rust
// Validates the cryptographic signature
sig_cert.verify_signature(
    webpki::RSA_PKCS1_2048_8192_SHA256,
    message,
    signature,
)?;

// ISSUE: Returns immediately without checking report content
Ok(())
```
The `RaReport` struct (in `report.rs`) exposes `timestamp`, `advisory_ids`, and `isv_enclave_quote_body`, but these are never checked against security policies.

**Recommended Follow-up:**
Refactor the verification logic to enforce checks for timestamp freshness, empty `advisory_ids` (no known CVEs), and enclave identity allowlisting within the `verify` path.

---

### 3. Missing Debug/Attribute Verification in DCAP
**ID:** `phala-blockchain@654b1b6:tee:attestation:003`  
**Status:** `needs_review` | **Severity:** `high` | **Confidence:** `high`  
**Files:** `crates/sgx-attestation/src/dcap.rs`, `crates/sgx-attestation/src/dcap/quote.rs`

**Core Observation:**
The DCAP verification logic explicitly skips checking the `attributes` and `misc_select` fields of the SGX report. This omission allows the system to accept enclaves running in Debug mode or with non-standard initialization states, bypassing critical security guarantees.

**Evidence:**
In `crates/sgx-attestation/src/dcap.rs`, the `verify` function contains comments indicating the intentional skip:
```rust
// skip verify_misc_select_field
// skip verify_attributes_field
```
The `EnclaveReport` struct defines `attributes` (which contains the Debug flag) and `misc_select`, but these are not verified against a security policy. The `pruntime_hash` is constructed using `mr_enclave` and `mr_signer`, but the configuration state is ignored.

**Recommended Follow-up:**
Update the code to explicitly verify that the `DEBUG` bit in `attributes.flags` is cleared (0) and that the `INIT` bit in `misc_select` is set as required. If this behavior is intentional, document the security implications clearly.

---

### 4. Unsafe Error Handling in Master Key Unsealing
**ID:** `phala-blockchain@654b1b6:tee:key_management:005`  
**Status:** `confirmed_candidate` | **Severity:** `high` | **Confidence:** `high`  
**Files:** `crates/phactory/src/system/master_key.rs`

**Core Observation:**
The `MasterKey` management module uses `expect()` and `assert!()` for cryptographic operations and I/O. This allows an attacker with write access to storage (or data corruption events) to trigger a panic in the TEE, causing a Denial of Service (DoS).

**Evidence:**
In `crates/phactory/src/system/master_key.rs`:
- Line 88-89: `sys.unseal_data(...).expect("Unseal master key failed")`
- Line 99: `MasterKeySeal::decode(...).expect("Failed to decode sealed master key")`
- Lines 105, 118: `assert!(identity_key.verify_data(...), "Broken sealed master key")`

The documentation at line 50 even acknowledges this: `/// This function could panic a lot.`

**Recommended Follow-up:**
Refactor `try_unseal` and `seal` to return `Result<T, E>` instead of panicking. Handle errors gracefully at the call site to allow for recovery or secure failure modes.

---

### 5. Potential Missing Trust Boundary Revalidation
**ID:** `phala-blockchain@654b1b6:tee:boundary:004`  
**Status:** `needs_review` | **Severity:** `medium` | **Confidence:** `low`  
**Files:** `crates/phactory/src/prpc_service.rs`, `crates/phactory/src/contracts/pink.rs`

**Core Observation:**
The RPC entry points `GatekeeperService::sync_info` and `PinkContract::handle_query` are identified as trust boundaries. The provided code snippets do not show the implementation bodies of these functions, making it impossible to verify if attestation revalidation occurs upon entry.

**Evidence:**
The provided snippets (lines 1-80) show imports and struct definitions but lack the implementation logic for the target methods. While `validate_attestation_report` is imported in `prpc_service.rs`, its usage is not visible in the provided evidence.

**Recommended Follow-up:**
Manually review the full implementation of `GatekeeperService::sync_info` and `PinkContract::handle_query` to verify that `validate_attestation_report` or equivalent checks are invoked at the entry point.

---

### 6. DCAP Attestation Collateral Handling
**ID:** `phala-blockchain@654b1b6:tee:attestation:006`  
**Status:** `needs_review` | **Severity:** `high` | **Confidence:** `medium`  
**Files:** `standalone/pherry/src/lib.rs`

**Core Observation:**
The `attestation_to_report` function fetches attestation collateral from a remote URL but does not explicitly demonstrate cryptographic verification of the quote against this collateral within the provided file. Additionally, URL validation is weak (only checks for emptiness), raising concerns about SSRF or fetching malicious collateral.

**Evidence:**
In `standalone/pherry/src/lib.rs`:
- Line 784: `let collateral = get_collateral(pccs_url, &quote, timeout).await?;`
- Line 779: `if pccs_url.is_empty() { return Err(...) }`
There is no visible call to a verification function (e.g., `verify_quote`) within `attestation_to_report`.

**Recommended Follow-up:**
1.  Confirm where the quote is cryptographically verified against the collateral (likely in `sgx_attestation` crate) and review that implementation.
2.  Enhance URL validation for `pccs_url` to enforce HTTPS and allowlisted domains.

---

## Coverage Summary

**Audited Directories/Crates:**
- `pallets/phala/src/utils/` (Attestation validation logic)
- `crates/sgx-attestation/src/` (IAS and DCAP verification implementations)
- `crates/phactory/src/system/` (Master key management)
- `crates/phactory/src/` (PRPC service and contract interfaces)
- `standalone/pherry/src/` (Attestation processing)

**Scope / Limitations:**
- The review focused on the specific candidates identified in the planner metadata.
- For `pherry/src/lib.rs` and `prpc_service.rs`, analysis was limited to the provided code snippets; full function bodies were not visible in some cases.
- The audit assumes standard SGX/DCAP security properties unless explicitly violated by the code.

---

## Next Steps for Human Reviewer

1.  **Prioritize High-Confidence Findings:** Address findings 001, 002, 003, and 005 immediately as they represent clear, high-severity vulnerabilities in the TEE's security perimeter.
2.  **Verify Governance Controls:** specifically for finding 001, ensure the `opt_out_enabled` switch cannot be easily toggled in production environments.
3.  **Code Expansion for Low-Confidence Items:** Retrieve the full implementation of `GatekeeperService::sync_info` and `PinkContract::handle_query` to close the gap on finding 004.
4.  **Dependency Audit:** For finding 006, trace the execution flow into the `sgx_attestation` crate to ensure the verification step actually exists and is called correctly.