# CVE Application Drafts From Example Reviews

These are draft reports for human review before responsible disclosure. They
are not final vulnerability claims. Each draft calls out what still needs to be
confirmed before submission to a CNA, GitHub Security Advisory, or upstream
security contact.

## Submission Readiness Summary

| Draft | Candidate | Readiness | Recommendation |
| --- | --- | --- | --- |
| PHALA-DCAP-ATTRS | Phala Blockchain DCAP verifier skips `misc_select` and `attributes` checks | High | Best first disclosure candidate. |
| PHALA-MASTERKEY-DOS | Phala Blockchain master key unseal path panics on corrupted sealed data | Medium | Submit if attacker write/precondition is realistic in deployment. |
| QOS-UNVERIFIED-TIME | qos `timestamp_ms` trusts timestamp from unsafe-parsed attestation doc | Medium-low | Needs PoC showing attacker influence over timestamp or trust-boundary violation. |
| QOS-NONCELESS-ATTESTATION | qos post-boot attestation request uses `nonce: None` | Medium-low | Needs relying-party replay PoC; may be design risk if timestamp/public key binding is sufficient. |

## Draft PHALA-DCAP-ATTRS

### Title

Phala Blockchain SGX DCAP verifier does not validate enclave attributes or
`misc_select`, allowing policy bypass for debug or nonconforming enclaves.

### Affected Product

- Project: `phala-network/phala-blockchain`
- Reviewed commit: `654b1b6`
- Affected component: `crates/sgx-attestation/src/dcap.rs`
- Affected function: `verify`

Affected version range is not yet established. Before submission, confirm the
first vulnerable commit and whether current `main` or released tags still
contain the same behavior.

### Vulnerability Type

- CWE candidate: CWE-295 Improper Certificate Validation, CWE-345 Insufficient Verification of Data Authenticity, or CWE-693 Protection Mechanism Failure.
- Class: Incomplete remote attestation policy validation.

### Summary

The SGX DCAP verification path parses and cryptographically verifies quote
collateral, but explicitly skips validation of SGX report `misc_select` and
`attributes`. These fields encode enclave configuration properties such as
debug mode and other attribute bits. If the verifier output is used to trust a
worker/runtime, a quote from an enclave with disallowed attributes may be
accepted as valid.

### Technical Details

In `crates/sgx-attestation/src/dcap.rs`, the verifier contains the following
security-relevant comments in the verification path:

```rust
// Seems we verify MR_ENCLAVE and MR_SIGNER is enough
// skip verify_misc_select_field
// skip verify_attributes_field
```

The function proceeds with collateral/certificate/signature checks and later
constructs `pruntime_hash` from `mr_enclave`, `isv_prod_id`, `isv_svn`, and
`mr_signer`, but it does not enforce an expected `attributes` mask or
`misc_select` policy.

Reviewed source:

- <https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-attestation/src/dcap.rs#L27-L53>

### Security Impact

An attacker who can present a DCAP quote for an enclave with the expected
measurement/signing identity but disallowed configuration may be accepted by
the verifier. The most important suspected impact is accepting a debug enclave
or an enclave with unexpected SGX attributes as trusted production code.

The exact impact depends on:

- Whether production deployments rely on this verifier for worker admission or
  trust decisions.
- Whether expected enclave identity alone is considered sufficient in Phala's
  threat model.
- Whether debug mode or other forbidden attributes can be combined with an
  otherwise allowed `mr_enclave`/`mr_signer` in the affected deployment.

### Attack Preconditions

- Attacker can submit a DCAP quote to the verifier.
- The submitted quote passes collateral/signature and measurement checks.
- The quote contains attributes or `misc_select` values that should be rejected
  by production policy.
- A downstream trust decision uses the verifier result without independently
  enforcing these fields.

### Proof-of-Concept Outline

1. Generate or obtain a DCAP quote for an enclave whose `mr_enclave`/`mr_signer`
   satisfy the allowlist, but whose `attributes.flags` includes a disallowed
   bit such as DEBUG.
2. Submit the quote and collateral to the affected `verify` function.
3. Observe that verification does not reject based on `attributes` or
   `misc_select`.
4. Confirm that the returned `ConfidentialReport` or verifier output is treated
   as acceptable by the caller.

This PoC still needs to be implemented against an affected build.

### Suggested Fix

- Add explicit policy checks for `misc_select` and `attributes` using masks,
  similar to Intel DCAP/QVL policy validation.
- Reject debug enclaves in production unless explicitly configured otherwise.
- Include these fields in tests with negative fixtures for debug and
  nonconforming attribute cases.
- Document any intentionally allowed non-default attributes.

### Tentative Severity

High, if verifier output gates production trust. Tentative CVSS:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1

If attacker must already control an allowed signer or local deployment
configuration, severity should be reduced.

### Disclosure Questions

- Is this verifier used in production worker admission?
- Are debug enclaves or non-default SGX attributes explicitly allowed anywhere?
- Which release first introduced the skip?
- Has this already been fixed or superseded by a newer attestation stack?

## Draft PHALA-MASTERKEY-DOS

### Title

Phala Blockchain master key recovery path panics on malformed sealed key data,
causing denial of service.

### Affected Product

- Project: `phala-network/phala-blockchain`
- Reviewed commit: `654b1b6`
- Affected component: `crates/phactory/src/system/master_key.rs`
- Affected functions: `seal`, `try_unseal`

Affected version range is not yet established.

### Vulnerability Type

- CWE candidate: CWE-248 Uncaught Exception, CWE-755 Improper Handling of Exceptional Conditions.
- Class: Denial of service through panic in security-critical state recovery.

### Summary

The master key sealing/unsealing code uses `expect` and `assert!` in the
recovery path. If sealed master key storage is malformed, corrupted, or has an
invalid integrity signature, the process panics instead of returning a
recoverable error. In deployments where an attacker can influence sealed
storage or trigger recovery on corrupted data, this can cause denial of
service for the TEE service.

### Technical Details

The reviewed code includes:

- `sys.seal_data(...).expect("Seal master key failed")`
- `sys.unseal_data(...).expect("Unseal master key failed")`
- `MasterKeySeal::decode(...).expect("Failed to decode sealed master key")`
- `assert!(identity_key.verify_data(...), "Broken sealed master key")`
- `assert!(identity_key.verify_data(...), "Broken sealed master key history")`

Reviewed source:

- <https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/phactory/src/system/master_key.rs#L45-L117>

The source comment above `try_unseal` also states that the function "could
panic a lot."

### Security Impact

Malformed or corrupted sealed key data can terminate the process during key
recovery. This can prevent service startup or recovery and cause availability
loss. The vulnerability is strongest if sealed storage is outside the enclave
trust boundary and can be modified by an untrusted host, compromised volume, or
fault injection.

### Attack Preconditions

- Attacker can modify, corrupt, replace, or truncate the sealed master key file,
  or can influence the sealing backend to return malformed data.
- The service calls `try_unseal` during startup, handover, or recovery.
- A panic terminates or restarts the service in a way that causes meaningful
  outage.

### Proof-of-Concept Outline

1. Locate the sealed master key file used by `master_key_file_path`.
2. Replace it with random bytes or a validly encoded `MasterKeySeal` with an
   invalid signature.
3. Start or trigger the component that calls `try_unseal`.
4. Observe panic at decode or signature verification instead of a returned
   error.

This PoC still needs to be implemented against an affected deployment.

### Suggested Fix

- Change `seal` and `try_unseal` to return `Result`.
- Replace `expect` and `assert!` with typed errors.
- Treat invalid sealed data as a security event and fail closed without
  panicking the process.
- Add tests for malformed sealed data, invalid signatures, truncated files,
  and sealing backend failures.

### Tentative Severity

Medium to High depending on attacker access to sealed storage. Tentative CVSS
for local untrusted-storage modification:

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 5.5

If a remote or low-privileged actor can influence the sealed file, severity may
be higher.

### Disclosure Questions

- Is sealed storage considered attacker-controlled or host-controlled in the
  deployment threat model?
- Does a panic kill the enclave/service or trigger clean recovery?
- Is master key storage protected by filesystem permissions, measured storage,
  or host policy?

## Draft QOS-UNVERIFIED-TIME

### Title

QuorumOS derives trusted current time from an unsafe-parsed Nitro attestation
document without verifying its signature.

### Affected Product

- Project: `tkhq/qos`
- Reviewed commit: `df1e355`
- Affected component: `src/qos_nsm/src/nsm.rs`
- Affected function: `NsmProvider::timestamp_ms` implementation for `Nsm`

Affected version range is not yet established.

### Vulnerability Type

- CWE candidate: CWE-345 Insufficient Verification of Data Authenticity, CWE-347 Improper Verification of Cryptographic Signature, CWE-829 Inclusion of Functionality from Untrusted Control Sphere.
- Class: Trusting unverified attestation metadata for freshness decisions.

### Summary

The `timestamp_ms` implementation obtains a Nitro attestation document with no
nonce, parses it using `unsafe_attestation_doc_from_der`, and returns the
embedded timestamp without verifying the attestation document signature or
certificate chain. This timestamp is later used as the current time for
verifying another attestation document. If an attacker can influence the NSM
provider response, this may allow backdating or time manipulation in
attestation verification.

### Technical Details

In `src/qos_nsm/src/nsm.rs`, `timestamp_ms` requests an attestation document:

```rust
types::NsmRequest::Attestation {
    user_data: None,
    nonce: None,
    public_key: None,
}
```

It then parses the returned DER with:

```rust
nitro::unsafe_attestation_doc_from_der(&document)?
```

and returns:

```rust
Ok(attestation_document.timestamp)
```

Reviewed source:

- <https://github.com/tkhq/qos/blob/df1e355/src/qos_nsm/src/nsm.rs#L41-L54>

The timestamp is consumed by
`verify_and_extract_attestation_doc_from_der` in `key.rs` to derive
`current_time_seconds` for attestation verification:

- <https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/key.rs#L280-L290>

### Security Impact

If the `NsmProvider` output can be spoofed, replaced, or implemented by an
untrusted provider, the verifier may use attacker-controlled time when checking
attestation validity windows. This could permit stale or expired attestation
documents to be accepted or valid documents to be rejected.

Impact is lower if the production `Nsm` implementation always talks directly
to a trusted local Nitro Secure Module and the OS/device boundary is considered
trusted.

### Attack Preconditions

- Attacker can influence `nsm_process_request` output, substitute an
  `NsmProvider`, compromise the NSM device path, or otherwise control the DER
  document passed to `unsafe_attestation_doc_from_der`.
- The returned timestamp is used to validate a security-sensitive remote
  attestation document.
- No independent trusted time source or monotonicity check exists.

### Proof-of-Concept Outline

1. Implement or inject a malicious `NsmProvider` that returns an attestation
   response containing a forged or stale timestamp.
2. Trigger `verify_and_extract_attestation_doc_from_der`.
3. Show that the forged timestamp is accepted as `current_time_seconds`.
4. Demonstrate acceptance of an attestation document that should be expired or
   outside the valid time window.

This PoC is required before CVE submission; without it, the issue may be
classified as a hardening concern.

### Suggested Fix

- Do not derive trusted time from an unsafe-parsed attestation document.
- Use a trusted monotonic or platform time source appropriate to the threat
  model.
- If an attestation document must be used, verify its signature and certificate
  chain before trusting the timestamp.
- Add nonce/challenge binding to the local attestation request.
- Constrain or seal the `NsmProvider` abstraction so production code cannot use
  untrusted providers for time.

### Tentative Severity

Medium if attacker can influence `NsmProvider` or NSM response. Tentative
CVSS:

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = 5.5

Severity can rise if a remote path can influence the provider response, or
fall if NSM/OS access is fully trusted.

### Disclosure Questions

- Can any production code use a non-hardware `NsmProvider`?
- Is `/dev/nitro_enclaves` or equivalent NSM access in the trusted computing
  base?
- What security decisions depend on `timestamp_ms`?
- Is there already a trusted time source in the architecture?

## Draft QOS-NONCELESS-ATTESTATION

### Title

QuorumOS post-boot Nitro attestation documents are generated without verifier
nonces, weakening replay resistance.

### Affected Product

- Project: `tkhq/qos`
- Reviewed commit: `df1e355`
- Affected component: `src/qos_core/src/protocol/services/attestation.rs`
- Affected functions: `live_attestation_doc`, `get_post_boot_attestation_doc`

Affected version range is not yet established.

### Vulnerability Type

- CWE candidate: CWE-294 Authentication Bypass by Capture-replay, CWE-345 Insufficient Verification of Data Authenticity.
- Class: Missing challenge freshness in remote attestation.

### Summary

The post-boot attestation request includes application-specific `user_data`
and an ephemeral public key, but sets `nonce: None`. Without a verifier-supplied
nonce or equivalent challenge, relying parties may be unable to distinguish a
fresh attestation document from a replayed one for the same manifest and key
material.

### Technical Details

In `src/qos_core/src/protocol/services/attestation.rs`,
`get_post_boot_attestation_doc` constructs:

```rust
NsmRequest::Attestation {
    user_data: Some(manifest_hash),
    nonce: None,
    public_key: Some(ephemeral_public_key),
}
```

Reviewed source:

- <https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/attestation.rs#L23-L33>

### Security Impact

If relying parties accept this attestation document as proof of a live current
enclave instance, an attacker may replay an older valid document for the same
manifest. This could weaken freshness guarantees during provisioning or
post-boot verification.

The impact depends on whether other signed fields provide sufficient freshness:

- Nitro attestation documents include timestamps.
- `public_key` binds the attestation to an ephemeral key.
- If the ephemeral key changes on each boot and relying parties encrypt only to
  the attested public key, replay may be less exploitable.

### Attack Preconditions

- Attacker can capture a previously valid post-boot attestation document.
- A relying party accepts attestation without a challenge nonce or strict
  freshness window.
- The replayed document's `user_data` and `public_key` remain useful to the
  attacker or target workflow.

### Proof-of-Concept Outline

1. Capture a valid post-boot attestation document for a manifest.
2. Replay the document to a relying party during a later provisioning or
   verification flow.
3. Demonstrate that the relying party accepts it without requiring a fresh
   challenge nonce.
4. Demonstrate a concrete security consequence, such as provisioning a secret
   to an unintended or stale instance.

This PoC is necessary before CVE submission. Without relying-party acceptance,
the issue may be treated as an architectural hardening recommendation.

### Suggested Fix

- Accept a verifier-provided nonce/challenge in `live_attestation_doc` and
  `get_post_boot_attestation_doc`.
- Include the nonce in the `NsmRequest::Attestation`.
- Require relying parties to reject missing, reused, or stale nonces.
- Preserve `user_data` and `public_key` binding, but do not treat them as a
  replacement for freshness.

### Tentative Severity

Medium to High depending on relying-party behavior. Tentative CVSS, if replay
can cause secret provisioning to a stale or unauthorized context:

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1

If timestamps and ephemeral-key binding prevent practical replay, severity
should be reduced or the issue should not be submitted as a CVE.

### Disclosure Questions

- Which relying parties consume `live_attestation_doc` output?
- Do relying parties enforce timestamp freshness?
- Is the ephemeral public key regenerated on every boot and never reused?
- Can a replayed document cause key shares or secrets to be released?

