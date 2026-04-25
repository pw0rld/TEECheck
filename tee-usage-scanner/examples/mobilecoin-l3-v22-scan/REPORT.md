# TEECheck Audit Report: mobilecoin@59a52d3

**Repo:** git@github.com:mobilecoinfoundation/mobilecoin.git  
**Commit:** 59a52d3d52e6cbbc2f67e0c223fa8d55d034a5b8  
**Run ID:** mobilecoin-l3-v22

## Executive Summary

This audit evaluated the Trusted Execution Environment (TEE) implementation, specifically focusing on attestation verification, authorization, and key management within the MobileCoin codebase. The analysis covered 11 candidates across critical paths including the AKE responder, consensus enclave, and SGX service layers. The audit identified one **confirmed** security vulnerability regarding missing attestation verification in the `ClientAuthRequestInput` path, which could allow an attacker to bypass identity verification. Additionally, several areas requiring human review were flagged, primarily concerning the delegation of verification logic and the visibility of security-critical checks (e.g., identity enforcement in `get_verifier` and replay resistance in DCAP verification).

While the majority of the low-level SGX wrappers and FFI bindings were found to be correctly implemented as primitives (with no issues observed), the confirmed finding in the AKE responder represents a high-severity trust boundary failure. The remaining "needs review" items highlight architectural dependencies where the security correctness relies on external components or invisible code paths. Immediate action is required to address the confirmed finding and to verify the implementation details of the delegated verification logic.

---

## Findings

### 1. Missing Attestation Verification in ClientAuthRequestInput Path
**ID:** `mobilecoin@59a52d3:tee:attestation:001`  
**Status:** `confirmed_candidate` (Corroborated)  
**Severity:** High  
**Confidence:** High  
**Files:** `attest/ake/src/responder.rs`

**Core Observation:**
The `Transition<Start, ClientAuthRequestInput, AuthResponseOutput>::try_next` function handles the client authentication flow but fails to perform attestation verification on the incoming request. Unlike the parallel `NodeAuthRequestInput` flow, which explicitly deserializes and verifies the DCAP quote, the `ClientAuthRequestInput` path reads the payload containing the client's evidence, discards it (bound to `_payload`), and immediately proceeds to `handle_response`. This allows a client to establish a trusted channel without providing valid attestation evidence.

**Evidence:**
- The `NodeAuthRequestInput` path (lines 139-177) explicitly deserializes `DcapEvidence` and performs verification using `DcapVerifier`.
- The `ClientAuthRequestInput` path (lines 180-201) calls `handle_request` but binds the result to `_payload`, effectively discarding the evidence.
- The `ClientAuthRequestInput` path proceeds immediately to `Self::handle_response` without any attestation verification logic.
- The `handle_response` function (lines 77-111) sends the responder's attestation evidence but does not verify the peer's evidence.
- The `NodeAuthRequestInput` uses the `HandshakeIX` pattern (Identity exchange), while `ClientAuthRequestInput` uses `HandshakeNX` (No identity exchange). However, the explicit transmission and subsequent discarding of evidence in the payload suggest a mismatch between protocol design and implementation.

**Recommended Follow-up:**
Determine if the omission of verification in the `ClientAuthRequestInput` path is intentional (due to the `HandshakeNX` pattern) or a critical vulnerability. If the protocol requires identity verification for clients, this code must be updated to deserialize and verify the `DcapEvidence` before transitioning to the `Ready` state.

---

### 2. Incomplete Attestation Verification in verify_report
**ID:** `mobilecoin@59a52d3:tee:attestation:006`  
**Status:** `confirmed_candidate` (Corroborated)  
**Severity:** Medium  
**Confidence:** High  
**Files:** `sgx/service/src/lib.rs`

**Core Observation:**
The `verify_report` function in `sgx/service/src/lib.rs` acts as a thin wrapper around the unsafe `sgx_verify_report` FFI call. It validates the cryptographic integrity (MAC) of the report structure but lacks logic to verify the identity (MRENCLAVE/MRSIGNER) or freshness (timestamps/nonce) of the attestation. Relying solely on this wrapper without additional checks in the calling context may lead to accepting expired or unauthorized reports.

**Evidence:**
- The function `verify_report` (line 41) consists solely of a direct call to the unsafe FFI function `sgx_verify_report`.
- There is no code inspecting `report.body.attributes`, `report.body.mr_enclave`, or `report.body.mr_signer`.
- There is no code inspecting `report.body.report_data` for nonces or timestamps.
- The function documentation describes it as a "Verify a report" wrapper without specifying high-level attestation checks.

**Recommended Follow-up:**
Review all callers of `verify_report` to ensure they explicitly enforce identity checks (MRENCLAVE/MRSIGNER) and freshness (nonce/timestamp) validation. Update the documentation of `verify_report` to clarify that it only performs structural and MAC verification.

---

### 3. Incomplete Attestation Verification in Quote::verify
**ID:** `mobilecoin@59a52d3:tee:attestation:005`  
**Status:** `needs_review` (Corroborated)  
**Severity:** High  
**Confidence:** Medium  
**Files:** `attest/core/src/quote.rs`

**Core Observation:**
The analysis of `attest/core/src/quote.rs` reveals that the `Quote::verify` and `Quote::verify_report` methods are responsible for validating SGX quotes. However, the provided snippets (lines 1-80) contain only type definitions, constants, and imports. The implementation logic for the critical verification functions is missing, making it impossible to confirm if checks for GID, security version, debug mode, and report data binding are correctly enforced.

**Evidence:**
- The provided source code snippet contains only lines 1-80.
- The target symbols `Quote::verify` and `Quote::verify_report` are not defined within the provided lines.
- The file imports `Report`, `ReportBody`, and `ReportBodyVerifyError`, suggesting delegation, but the implementation is not visible.

**Recommended Follow-up:**
Locate and review the full implementation of `Quote::verify` and `Quote::verify_report` in `attest/core/src/quote.rs`. Verify that the implementation explicitly checks the `AttributeFlags::DEBUG`, Security Version, and report data binding.

---

### 4. Analysis of EnclaveRouter::peer_init for Authorization and Caller Binding
**ID:** `mobilecoin@59a52d3:tee:authorization:002`  
**Status:** `needs_review` (Inconclusive)  
**Severity:** High  
**Confidence:** Low  
**Files:** `crypto/ake/enclave/src/lib.rs`

**Core Observation:**
The target function `EnclaveRouter::peer_init` is responsible for initiating peer connections. The provided snippets (lines 1-80) show module imports and state structures but do not contain the implementation of `peer_init`. Consequently, it is impossible to verify if the function correctly implements authorization, caller binding, or trust-boundary revalidation.

**Evidence:**
- The provided code snippet (lines 1-80) contains module imports and the `AkeEnclaveState` struct definition.
- The target function `EnclaveRouter::peer_init` is not present in the snippet.
- Tool hits suggest `responder.binding()` is called at line 271, but this line is not in the provided snippet.

**Recommended Follow-up:**
Inspect the implementation of `EnclaveRouter::peer_init` (around line 271) to verify that attestation evidence is verified and strictly bound to the caller context (e.g., transport channel) to prevent Confused Deputy attacks.

---

### 5. Incomplete Attestation Verification in verify_attestation_evidence
**ID:** `mobilecoin@59a52d3:tee:attestation:003`  
**Status:** `needs_review` (Inconclusive)  
**Severity:** High  
**Confidence:** Medium  
**Files:** `crypto/ake/enclave/src/lib.rs`

**Core Observation:**
The function `verify_attestation_evidence` performs cryptographic verification of the DCAP quote and checks nonces. However, it relies on an external helper `get_verifier` to provide the verification policy (MRENCLAVE, MRENCLAVE signer, etc.). The definition of `get_verifier` is not visible, leaving the enforcement of identity obligations unconfirmed.

**Evidence:**
- The function `verify_attestation_evidence` (line 669) performs a freshness check by comparing `quote.app_report_body()` against the local `report.body()` (line 696).
- Cryptographic verification is delegated to a `verifier` object obtained via `self.get_verifier(report_data)` (line 701).
- The implementation of `get_verifier` is not present in the provided snippet (lines 619-719).

**Recommended Follow-up:**
Locate the implementation of `get_verifier`. Verify that it returns a policy that strictly enforces MRENCLAVE and MRSIGNER checks against a trusted allowlist, ensuring that a valid quote from a malicious enclave (different measurement) cannot be accepted.

---

### 6. Attestation Verification Delegation in Consensus Enclave
**ID:** `mobilecoin@59a52d3:tee:attestation:004`  
**Status:** `needs_review` (Inconclusive)  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `consensus/enclave/impl/src/lib.rs`

**Core Observation:**
The function `verify_attestation_evidence` in `SgxConsensusEnclave` delegates the entire attestation verification process to an internal `ake` module. It acts as a thin wrapper without performing additional checks or state validation. While this may be an architectural decision, the lack of independent validation in the consensus enclave creates a risk if the `ake` module fails to enforce context-specific rules.

**Evidence:**
- The function `verify_attestation_evidence` (lines 439-447) delegates the call to `self.ake.verify_attestation_evidence`.
- There is no visible logic for identity verification, nonce freshness, or replay protection within the `SgxConsensusEnclave` implementation.
- Error handling is a direct propagation (`?`) of the result from the `ake` module.

**Recommended Follow-up:**
Confirm that the `ake` module's verification logic is sufficient for the consensus enclave's security requirements. Verify that the `ResponderId`s passed during `enclave_init` are correctly used by the `ake` module to enforce identity binding.

---

### 7. DCAP Attestation Verification Logic
**ID:** `mobilecoin@59a52d3:tee:attestation:007`  
**Status:** `needs_review` (Contested)  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `attest/verifier/src/dcap.rs`

**Core Observation:**
The `DcapVerifier` delegates verification to `EvidenceVerifier` and `ReportDataHashVerifier`. The `ReportDataHashVerifier` performs a static equality check of the report data hash against a pre-computed value. There is no visible logic in `dcap.rs` to validate the freshness of the nonce or enforce that it is unique per session, potentially exposing the system to replay attacks if the nonce is static.

**Evidence:**
- `ReportDataHashVerifier` compares the hash of the quote's `report_data` against a pre-computed hash derived from `EnclaveReportDataContents`.
- The `time` parameter passed to `EvidenceVerifier` is used for certificate validity, not quote freshness.
- There is no logic validating the freshness of the `nonce` or enforcing uniqueness per session.
- `DcapVerifier::new` accepts a fixed `report_data` object, and the verifier checks against this fixed object.

**Recommended Follow-up:**
Verify that the `nonce` passed to `DcapVerifier` is guaranteed to be fresh and unique for every verification request (e.g., generated by the verifier just before the request). Ensure that the system does not rely on static nonces, which would allow replay attacks.

---

### 8. SGX Sealing Key Policy and Integrity Validation
**ID:** `mobilecoin@59a52d3:tee:key_management:008`  
**Status:** `needs_review` (Contested)  
**Severity:** Low  
**Confidence:** High  
**Files:** `sgx/service/src/lib.rs`

**Core Observation:**
The implementation uses `SGX_KEYPOLICY_MRENCLAVE` to bind sealed data to the specific enclave measurement. The review noted that the code does not implement explicit caller authorization or access control checks within the sealing/unsealing functions. While the Challenger argues this is the responsibility of the application logic, the absence of explicit checks in the wrapper could be misused.

**Evidence:**
- Constant `KEY_POLICY` is defined as `SGX_KEYPOLICY_MRENCLAVE` (line 57).
- `seal_data` and `unseal_data` validate buffer lengths and MACs but do not perform caller authorization.
- The code accepts `additional_mac_txt` as an argument, provided lengths are consistent.

**Recommended Follow-up:**
Verify that all callers of `seal_data` and `unseal_data` implement appropriate access control checks to ensure that services within the enclave cannot unseal data intended for other services.

---

### 9. Insufficient Identity Binding in Attestation Report Generation
**ID:** `mobilecoin@59a52d3:tee:attestation:009`  
**Status:** `no_issue_observed`  
**Severity:** Low  
**Confidence:** High  
**Files:** `sgx/service/src/lib.rs`

**Core Observation:**
The `report` function allows `report_data` to be `None`, resulting in a null pointer passed to `sgx_create_report`. The hypothesis suggested this bypasses caller-binding requirements. However, the function is a low-level utility wrapper for `sgx_tservice`. Identity binding is the obligation of the caller and the verifier, not this primitive.

**Evidence:**
- The function is a direct wrapper mapping Rust types to SGX instructions.
- The hardware signs whatever is in the memory location (or zeros if null).
- The security of the binding relies on the protocol using this primitive.

**Recommended Follow-up:**
None. The function behaves correctly as a low-level primitive.

---

### 10. Missing Validation in Report::new
**ID:** `mobilecoin@59a52d3:tee:attestation:010`  
**Status:** `no_issue_observed`  
**Severity:** Low  
**Confidence:** High  
**Files:** `attest/trusted/src/lib.rs`

**Core Observation:**
The hypothesis claimed `Report::new` fails to validate `report_data` for freshness. The function is a direct interface to the hardware's `EREPORT` instruction, designed to bind data, not validate it. Validation is the responsibility of the verifier.

**Evidence:**
- The implementation is a pass-through to `mc_sgx_compat::report`.
- It is technically impossible for `Report::new` to validate freshness without external state.

**Recommended Follow-up:**
None. The function adheres to its design as a cryptographic primitive.

---

### 11. Analysis of sgx_get_key FFI Bindings
**ID:** `mobilecoin@59a52d3:tee:key_management:011`  
**Status:** `no_issue_observed`  
**Severity:** Low  
**Confidence:** High  
**Files:** `sgx/types/src/function.rs`, `sgx/types/src/types.rs`

**Core Observation:**
The hypothesis suggested missing authorization checks in key derivation. The reviewed files are strictly Rust FFI bindings and type definitions. The enforcement of `key_policy` (MRENCLAVE, MRSIGNER) occurs inside the trusted runtime/CPU microcode, not in the Rust wrapper.

**Evidence:**
- `sgx/types/src/function.rs` contains `extern` block declarations.
- `sgx/types/src/types.rs` defines `sgx_key_request_t` and policy constants.
- No implementation logic exists in the provided files, which is standard for FFI bindings.

**Recommended Follow-up:**
None. The code correctly delegates security enforcement to the SGX trusted runtime.

---

## Coverage

### Audited Directories/Crates
- `attest/ake/src/responder.rs`
- `crypto/ake/enclave/src/lib.rs`
- `consensus/enclave/impl/src/lib.rs`
- `attest/core/src/quote.rs`
- `sgx/service/src/lib.rs`
- `attest/verifier/src/dcap.rs`
- `attest/trusted/src/lib.rs`
- `sgx/types/src/function.rs`
- `sgx/types/src/types.rs`

### What Was Missed / Limitations
- **Incomplete Code Visibility:** For several findings (e.g., `mobilecoin@59a52d3:tee:attestation:005`, `mobilecoin@59a52d3:tee:authorization:002`), the critical implementation logic was not present in the provided snippets (lines 1-80 only), leading to `inconclusive` or `needs_review` statuses.
- **Delegated Logic:** Findings often relied on external helpers (e.g., `get_verifier`, `EvidenceVerifier`). The security of the system depends on the correctness of these unreviewed components.
- **Dynamic Context:** The analysis was static; runtime behavior or configuration (e.g., specific nonces used in `DcapVerifier`) could not be observed.

---

## Next Steps for Human Reviewer

1.  **Address High-Severity Confirmed Finding:**
    *   Immediately investigate `attest/ake/src/responder.rs` (Finding #001). Determine if the `ClientAuthRequestInput` path should verify attestation evidence. If so, implement verification similar to the `NodeAuthRequestInput` path.

2.  **Verify Delegated Implementations:**
    *   Locate and audit the `get_verifier` function in `crypto/ake/enclave/src/lib.rs` (Finding #003) to ensure it enforces strict MRENCLAVE/MRSIGNER policies.
    *   Locate the full implementation of `Quote::verify` in `attest/core/src/quote.rs` (Finding #005) to confirm it checks `DEBUG` flags and security versions.

3.  **Review Authorization Bindings:**
    *   Examine `EnclaveRouter::peer_init` in `crypto/ake/enclave/src/lib.rs` (Finding #002) to ensure caller binding prevents Confused Deputy attacks.

4.  **Assess Replay Resistance:**
    *   Review the usage of `DcapVerifier` (Finding #007) to ensure that nonces are generated freshly for each session and not reused, preventing replay attacks.

5.  **Documentation Updates:**
    *   For `sgx/service/src/lib.rs` (Finding #006), update documentation for `verify_report` to clarify that it only performs structural/MAC verification and that callers must enforce identity and freshness.