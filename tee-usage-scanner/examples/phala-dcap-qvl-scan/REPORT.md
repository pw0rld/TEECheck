# TEECheck Audit Report: dcap-qvl

**Repo:** git@github.com:Phala-Network/dcap-qvl.git  
**Commit:** 90c4c9ffd6fd1565b138df161ecdf6fe568a326c  
**Run ID:** phala-dcap-qvl-l3

## Executive Summary

This audit evaluated the `dcap-qvl` Rust crate, a library designed to verify Intel SGX DCAP quotes. The review focused on attestation logic, trust boundaries (FFI), and cryptographic validation. The analysis identified one **Confirmed** security candidate and six findings requiring **Human Review**.

The most critical finding (`attestation:001`) confirms the existence of a feature (`danger-allow-tcb-override`) that allows arbitrary modification of the Trusted Computing Base (TCB) status after cryptographic verification. This feature effectively bypasses the security decision-making process of the attestation flow, allowing a revoked or outdated enclave to be marked as safe. Additionally, several high-severity issues were identified regarding the handling of time sources during verification, the lack of verification in PCK certificate parsing, and potential gaps in FFI input validation. The audit also noted that while parsing logic is well-structured, it relies heavily on the caller to enforce strict separation between "parsed" and "verified" states, creating a risk of API misuse.

**Recommended Actions:**
1.  **Immediately** assess the necessity of the `danger-allow-tcb-override` feature. If possible, remove it or restrict it to prevent downgrading security status.
2.  Review the `verify` module to ensure that time parameters are derived from a trusted, monotonic source.
3.  Manually audit the FFI boundaries in `src/ffi.rs` and `src/python.rs` to ensure robust input validation and secure failure modes.

---

## Findings

### 1. TCB Status Override Bypass
**ID:** `dcap-qvl@90c4c9f:tee:attestation:001`  
**Status:** `confirmed_candidate`  
**Severity:** High  
**Confidence:** High  
**Files:** `src/verify.rs`

**Core Observation:**
The crate exposes a feature flag `danger-allow-tcb-override` that introduces the `dangerous_verify_with_tcb_override` method. This method allows a caller to modify the `TcbInfo` object—specifically fields like `tcb_status`—*after* the cryptographic signature has been verified but *before* the trust decision is made. This allows an attacker or compromised dependency to change a status of `Revoked` to `UpToDate`, bypassing the integrity of the attestation process.

**Evidence:**
*   The feature allows arbitrary modification of `TcbInfo` post-signature verification.
*   The conceptual flow demonstrates: `verify_tcb_info_signature` -> `override_tcb_info` -> `status check`.
*   The Challenger argued this is for testing/disaster recovery, but the supply chain risk remains high if enabled in production.

**Recommended Follow-up:**
Evaluate if this feature is strictly required for offline scenarios. If retained, refactor to prevent downgrading security status (e.g., only allow stricter overrides). Update documentation to explicitly state that enabling this feature invalidates the library's security guarantees.

---

### 2. Unverified PCK Certificate Parsing
**ID:** `dcap-qvl@90c4c9f:tee:attestation:005`  
**Status:** `needs_review`  
**Severity:** High  
**Confidence:** High  
**Files:** `src/intel.rs`

**Core Observation:**
The functions `parse_pck_extension` and `parse_pck_extension_from_pem` extract sensitive identity fields (PPID, CPU SVN, FMSPC) from PCK certificates but perform no signature verification, chain validation, or revocation checks. The code acts as a pure parser, returning unverified identity data. If the caller assumes a successful parse implies a trusted identity, the system is vulnerable.

**Evidence:**
*   `parse_pck_extension` (Line 68) checks for the *presence* of data but not its validity.
*   `parse_pck_extension_from_pem` (Line 94) extracts the leaf certificate without validating the chain of trust, expiration, or revocation.
*   The Challenger argued this is a separation of concerns (parser vs. verifier), but the lack of explicit documentation or enforcement regarding the need for external verification constitutes a security gap.

**Recommended Follow-up:**
Confirm that all callers of these functions perform full cryptographic validation (chain trust, expiration, CRL/OCSP) before using the extracted identity data. Add documentation to the functions warning that they return unverified data.

---

### 3. Timestamp Manipulation & Replay Risk
**ID:** `dcap-qvl@90c4c9f:tee:attestation:004`  
**Status:** `needs_review`  
**Severity:** High  
**Confidence:** Medium  
**Files:** `src/verify.rs`

**Core Observation:**
The verification functions `verify_tcb_info_signature` and `verify_qe_identity_signature` accept a `now` parameter to validate collateral freshness (`issue_date`, `next_update`). There is no evidence that this `now` parameter is enforced to be a trusted, monotonic time source. If a caller provides a backdated timestamp, the verifier might accept expired collateral or stale CRLs.

**Evidence:**
*   The code compares `now.as_secs()` against parsed timestamps.
*   No monotonic clock or trusted time source enforcement is visible within the module.
*   Additionally, the review notes that the binding between the PCK certificate and the QE Report signature (Step 4 of verification) was not fully visible in the provided snippets.

**Recommended Follow-up:**
Audit the callers of these functions to ensure `now` is derived from a secure time source. Verify that the logic binding the PCK leaf certificate public key to the QE Report signature is explicitly implemented and correct.

---

### 4. FFI Boundary Input Validation (C Interface)
**ID:** `dcap-qvl@90c4c9f:tee:boundary:002`  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/ffi.rs`

**Core Observation:**
The review investigated potential missing input validation and caller binding at the FFI boundary for `tee_qvl_verify_quote` and `tee_qvl_verify_quote_with_root_ca`. The provided code snippets (lines 1-80) contained only struct definitions, while the actual implementation logic is reported to exist later in the file (lines 359+). Consequently, it could not be verified if proper memory safety and input sanitization are performed.

**Evidence:**
*   The provided snippets only show struct definitions (`FfiQuote`, `FfiReport`).
*   The target symbols are not present in the reviewed snippets.
*   The Challenger noted that the logic likely exists later in the file, but this was not available for verification.

**Recommended Follow-up:**
Manually review the full implementation of `src/ffi.rs` (specifically lines 359+) to ensure that raw pointer conversions are safe, input lengths are validated, and that there is no risk of memory unsafety at the boundary.

---

### 5. Python FFI Input Validation
**ID:** `dcap-qvl@90c4c9f:tee:boundary:006`  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/python.rs`

**Core Observation:**
The Python FFI function `parse_quote` delegates directly to `PyQuote::parse` without performing explicit wrapper-level validation (e.g., length checks). While the function signature (`PyResult`) suggests errors are handled gracefully rather than panicking, the absence of visible input sanitization at the trust boundary requires verification.

**Evidence:**
*   Implementation at lines 579-580: `fn parse_quote(raw_quote: &Bound<'_, PyBytes>) -> PyResult<PyQuote> { PyQuote::parse(raw_quote) }`.
*   The Expert raised concerns about potential panics on malformed input; the Challenger argued that standard Rust parsers return `Result` types.
*   The Arbiter determined that while a panic is unlikely, the lack of explicit boundary checks warrants a review of the internal `PyQuote::parse` logic.

**Recommended Follow-up:**
Review the implementation of `PyQuote::parse` to ensure it handles malformed input robustly, enforces strict parsing limits, and does not perform unsafe operations (like `unwrap()` on untrusted data).

---

### 6. Collateral Verification Separation
**ID:** `dcap-qvl@90c4c9f:tee:attestation:003`  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/collateral.rs`

**Core Observation:**
The `src/collateral.rs` file handles fetching and deserializing DCAP collateral but does not contain explicit logic for signature verification, CRL validation, or freshness checks. The code relies on `serde_json::Value` for deferred parsing. The security risk depends on whether the data is used *before* verification occurs in a separate module.

**Evidence:**
*   Structs for TCB Info and QE Identity include `signature` fields, but no validation logic is present in the file.
*   The Challenger argued this is a valid separation of concerns, with verification delegated to a `verify` module.

**Recommended Follow-up:**
Trace the usage of `QuoteCollateralV3` returned by `get_collateral` to confirm that signature verification and CRL checks are mandatory and occur before any trust decisions are made. Ensure strict schema validation happens immediately after deserialization.

---

### 7. Quote Parsing vs. Verification State
**ID:** `dcap-qvl@90c4c9f:tee:attestation:007`  
**Status:** `needs_review`  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/quote.rs`

**Core Observation:**
The `Quote` struct and `Quote::parse` method focus exclusively on deserializing byte streams. There is no mechanism to track verification status (e.g., `ParsedQuote` vs `VerifiedQuote`). This creates a risk where a user might consume a parsed quote assuming it is cryptographically valid.

**Evidence:**
*   The `Quote` struct is a data container without an `is_verified` field.
*   `Quote::parse` returns `scale::Error` for format issues but performs no security checks.
*   The Challenger argued this is a Data Transfer Object (DTO) pattern, but the Arbiter noted the risk of API misuse.

**Recommended Follow-up:**
Consider adding a type-level state to enforce that verification occurs before the quote data can be used. Ensure documentation clearly states that `Quote::parse` does not imply the quote is cryptographically valid.

---

## Coverage

### Directories/Crates Audited
*   `src/verify.rs` - Core attestation verification logic, TCB validation, signature handling.
*   `src/ffi.rs` - C FFI boundary definitions and entry points.
*   `src/collateral.rs` - Collateral fetching and parsing logic.
*   `src/intel.rs` - Intel SGX specific parsing (PCK certificates).
*   `src/python.rs` - Python bindings (PyO3).
*   `src/quote.rs` - Quote structure definitions and parsing.

### What Was Missed / Out of Scope
*   Full implementation of `src/ffi.rs` (lines 359+) was not visible in the provided packets for FFI boundary review.
*   Internal implementation of `PyQuote::parse` in `src/python.rs` was not fully visible.
*   External dependencies (e.g., `webpki`, `serde`) were assumed to be correctly used but not audited independently.
*   Integration tests or usage examples were not reviewed.

---

## Next Steps for Human Reviewer

1.  **Address `attestation:001`:** Decide the fate of the `danger-allow-tcb-override` feature. Document the decision clearly.
2.  **Verify Time Handling (`attestation:004`):** Ensure the `now` parameter in verification functions is sourced securely.
3.  **Audit FFI Safety (`boundary:002`, `boundary:006`):** Complete the manual review of the FFI implementations in `src/ffi.rs` and `src/python.rs` to confirm memory safety and input validation.
4.  **Verify Data Flow (`attestation:003`, `attestation:005`, `attestation:007`):** Trace the data flow from parsing to verification to ensure unverified data cannot be accidentally used for trust decisions. Consider enforcing type states for verified quotes.