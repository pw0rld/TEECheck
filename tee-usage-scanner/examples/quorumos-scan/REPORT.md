# TEECheck Audit Report

**Repo:** `git@github.com:tkhq/qos.git`  
**Commit:** `df1e355d736b13fb5e9bb72011825f9587da698c`  
**Run ID:** `quorumos-l3`

## Executive Summary

This audit evaluated the Trusted Execution Environment (TEE) implementation, specifically focusing on attestation flows, key management, and FFI boundaries within the `qos` codebase. The review identified critical weaknesses in the attestation architecture, most notably the generation of attestation documents without nonces, rendering the system vulnerable to replay attacks. Additionally, a high-severity issue was confirmed where the `validate_manifest` function accepts an attestation document but fails to utilize it for identity verification, effectively breaking the chain of trust during state transitions.

While the core cryptographic operations and hardware abstraction layers show signs of defensive design, the reliance on `unsafe` parsing methods for attestation documents and the delegation of critical authorization checks to opaque or unverified logic present significant security risks. The findings indicate that while the system may correctly handle data integrity, it lacks sufficient enforcement of freshness and identity binding in several critical paths.

**Recommended Actions:** Immediate remediation is required to introduce nonces into all attestation requests and to implement verification logic within `validate_manifest`. Furthermore, a manual review of the FFI boundary assumptions and the `inject_key` authorization flow is strongly recommended to ensure the threat model is fully covered.

---

## Findings

### 1. Missing Replay Resistance in Attestation Generation
**ID:** `qos@df1e355:tee:attestation:001`  
**Status:** `confirmed_candidate` (Corroborated)  
**Severity:** High  
**Confidence:** High  
**Files:** `src/qos_core/src/protocol/services/attestation.rs`, `src/qos_core/src/protocol/services/boot.rs`

**Core Observation:**
The target application generates Nitro Enclave attestation documents without a nonce, rendering them vulnerable to replay attacks. The enclave functions responsible for generating these documents (`get_post_boot_attestation_doc`) and exposing them (`live_attestation_doc`, `put_manifest_and_pivot`) do not perform internal verification of the attestation response. While the inclusion of `user_data` (manifest hash) binds the attestation to a specific configuration, it fails to provide freshness guarantees.

**Evidence:**
*   **Missing Nonce:** In `src/qos_core/src/protocol/services/attestation.rs`, the function `get_post_boot_attestation_doc` initializes the attestation request with `nonce: None`.
    ```rust
    NsmRequest::Attestation { nonce: None, user_data: ... }
    ```
*   **Lack of Internal Verification:** In `src/qos_core/src/protocol/services/boot.rs`, the function `put_manifest_and_pivot` calls `get_post_boot_attestation_doc` and returns the resulting `NsmResponse` immediately. It does not validate the certificate chain or the document's signature before returning it.
*   **Insufficient Mitigations:** Arguments that `user_data` prevents replay are insufficient because it only ensures the attestation corresponds to the *correct* manifest, not that it is fresh. A valid attestation for a specific state can be replayed indefinitely.

**Recommended Follow-up:**
1.  Modify `get_post_boot_attestation_doc` to accept a `nonce` argument and pass it to the NSM request.
2.  Ensure callers provide a fresh nonce for every attestation request.
3.  Implement verification logic within the enclave to validate the NSM certificate chain and document signature before trusting the content.

---

### 2. Unused Attestation Document in Manifest Validation
**ID:** `qos@df1e355:tee:attestation:002`  
**Status:** `confirmed_candidate` (Corroborated)  
**Severity:** High  
**Confidence:** High  
**Files:** `src/qos_core/src/protocol/services/key.rs`

**Core Observation:**
The `validate_manifest` function accepts an attestation document intended to verify the identity of the enclave requesting a manifest update but fails to utilize it in any validation logic. This omission breaks the chain of trust between the enclave's identity and the state transition, relying solely on the manifest's internal signatures.

**Evidence:**
*   **Unused Variable:** The function signature includes `attestation_doc`, but it is marked with `#[allow(unused_variables)]` and is not referenced in the function body.
    ```rust
    fn validate_manifest(
        new_manifest_envelope: &ManifestEnvelope, 
        old_manifest_envelope: &ManifestEnvelope, 
        #[allow(unused_variables)] attestation_doc: &AttestationDoc
    )
    ```
*   **Broken Authorization:** The validation logic consists only of checking approvals on the new manifest envelope, verifying share set approvals, and matching the Quorum Key. It does not verify that the request originates from a genuine, secure enclave.
*   **TOCTOU Risk:** The binding of the attestation to the encryption key happens *after* `validate_manifest` returns, creating a Time-of-Check-Time-of-Use issue where state is updated based on unverified identity.

**Recommended Follow-up:**
Modify `validate_manifest` to cryptographically verify that the `attestation_doc` (specifically the report data or user data within it) binds the requester to the `new_manifest_envelope` or the specific action being performed.

---

### 3. Blind Trust in Unsafe Attestation Parsing
**ID:** `qos@df1e355:tee:attestation:006`  
**Status:** `confirmed_candidate` (Corroborated)  
**Severity:** High  
**Confidence:** High  
**Files:** `src/qos_nsm/src/nsm.rs`

**Core Observation:**
The `timestamp_ms` function trusts attestation data without cryptographic verification. It parses a raw DER document using an unsafe method and returns the timestamp immediately, exposing the system to replay attacks and data spoofing. The function signature prevents the caller from performing verification, as only the `u64` timestamp is returned.

**Evidence:**
*   **No Nonce:** The request is sent with `nonce: None`.
*   **Unsafe Parsing:** The code uses `nitro::unsafe_attestation_doc_from_der`, which parses the structure without verifying the cryptographic signature.
*   **Blind Trust:** The timestamp is extracted and returned immediately upon parsing.
    ```rust
    fn timestamp_ms(&self) -> Result<u64, nitro::AttestError> {
        let request = Attestation { nonce: None, .. };
        let doc_bytes = nsm_process_request(request)?;
        let doc = nitro::unsafe_attestation_doc_from_der(doc_bytes)?;
        Ok(doc.timestamp)
    }
    ```
*   **Delegation Debunked:** The argument that verification is delegated to the caller is invalid because the caller never sees the attestation document or certificates.

**Recommended Follow-up:**
Refactor `timestamp_ms` to verify the certificate chain and document signature before extracting the timestamp. Alternatively, return the full document to the caller to allow for proper verification context.

---

### 4. Potential Insufficient Caller Binding in Key Injection
**ID:** `qos@df1e355:tee:key_management:003`  
**Status:** `needs_review` (Contested)  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/qos_core/src/protocol/services/key.rs`

**Core Observation:**
The function `inject_key` verifies the signature against the manifest's quorum key but does not explicitly verify the identity or authorization of the caller invoking the function. While the function is internal (`pub(in crate::protocol)`), there is a debate regarding whether the transport layer provides sufficient guarantees or if explicit caller binding is required within the enclave.

**Evidence:**
*   **Internal Visibility:** The function is restricted to `pub(in crate::protocol)`, suggesting it is not a public RPC endpoint.
*   **Cryptographic Validation:** The function verifies the signature over `encrypted_quorum_key` and ensures the decrypted key matches the manifest.
*   **Architectural Conflict:** The Expert asserts that the lack of explicit caller authorization is a vulnerability for a critical state transition. The Challenger argues that authorization is handled by the enclave boundary and transport layer, making internal ACLs redundant.

**Recommended Follow-up:**
Conduct a manual review to validate the transport layer guarantees and the call graph of `inject_key`. Confirm that only authenticated entry points can invoke this function and that the architecture guarantees a 1:1 mapping between external requests and internal calls.

---

### 5. Opaque Authorization Logic in Key Export
**ID:** `qos@df1e355:tee:key_management:004`  
**Status:** `needs_review` (Contested)  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/qos_core/src/protocol/services/key.rs`

**Core Observation:**
The `export_key` function delegates critical authorization steps to `validate_manifest`. However, the implementation of `validate_manifest` was not visible in the evidence provided. Consequently, it is impossible to confirm if the attestation is properly bound to the manifest's identity (e.g., checking MRENCLAVE, MRSIGNER).

**Evidence:**
*   **Delegation:** `export_key` validates cryptographic integrity and freshness of the attestation but delegates the specific authorization of the export to `validate_manifest`.
*   **Missing Implementation:** The source code for `validate_manifest` was absent from the review packet.
*   **Gap:** Without seeing `validate_manifest`, it cannot be verified that the caller is properly bound to the key or that the attestation is checked against enclave identity properties.

**Recommended Follow-up:**
Perform a manual review of the `validate_manifest` implementation to ensure it cryptographically binds the attestation document to the manifest's identity (MRENCLAVE/MRSIGNER) before authorizing the key export.

---

### 6. Trust Boundary Assumptions in FFI Bridge
**ID:** `qos@df1e355:tee:boundary:005`  
**Status:** `needs_review` (Contested)  
**Severity:** Medium  
**Confidence:** Medium  
**Files:** `src/qos_nsm/src/nsm.rs`

**Core Observation:**
The `nsm_process_request` function acts as a direct wrapper around the Nitro Secure Module (NSM) driver without performing application-level trust-boundary revalidation. The Challenger argues that authorization is handled by OS ACLs on the device file and the hardware itself, making application checks redundant. However, the lack of explicit documentation or type-level enforcement of these boundary assumptions represents a potential risk if the `NsmProvider` trait is implemented by other components (e.g., remote proxies).

**Evidence:**
*   **Direct Pass-Through:** The implementation calls `nsm::driver::nsm_process_request(fd, request.into()).into()` without intermediate logic.
*   **OS Reliance:** Security relies on `nsm_init()` failing if the caller lacks permissions for `/dev/nitro_enclaves`.
*   **Trait Risk:** The `NsmProvider` trait allows for mocking or alternative implementations. If an implementation bypasses the hardware driver, the lack of interface requirements for authorization becomes a vulnerability.

**Recommended Follow-up:**
Review the architecture to confirm that no other implementations of `NsmProvider` exist that bypass the hardware driver. Verify that OS permissions on `/dev/nitro_enclaves` are strictly sufficient for the threat model and document these assumptions explicitly.

---

## Coverage

### Directories and Crates Audited
*   `src/qos_core/src/protocol/services/attestation.rs`
*   `src/qos_core/src/protocol/services/boot.rs`
*   `src/qos_core/src/protocol/services/key.rs`
*   `src/qos_nsm/src/nsm.rs`

### Scope and Limitations
*   **In-Scope:** Attestation generation, manifest validation logic, key injection/export flows, and the FFI boundary to the Nitro Secure Module driver.
*   **Missed/Out-of-Scope:** The implementation of `validate_manifest` (referenced but not analyzed in Packet 4), the specific transport/RPC layer handling authorization for `inject_key`, and the broader OS-level configuration of `/dev/nitro_enclaves`.

---

## Next Steps

1.  **Immediate Remediation (High Severity):**
    *   Refactor attestation generation to include mandatory nonces.
    *   Implement verification logic in `validate_manifest` to actually use the provided attestation document.
    *   Replace `unsafe_attestation_doc_from_der` with verified parsing in `timestamp_ms`.

2.  **Manual Review (Medium Severity):**
    *   Trace the call graph for `inject_key` to verify transport-layer authorization assumptions.
    *   Locate and audit the source code for `validate_manifest` to ensure proper identity binding.
    *   Audit the `NsmProvider` trait implementations to ensure no insecure proxies exist.

3.  **Documentation:**
    *   Document the security assumptions regarding OS-level permissions for the NSM driver interface.