# MobileCoin TEE Security Audit Report (v2)

**Project**: MobileCoin
**Date**: 2026-04-16
**Framework**: tee-web3-audit v2 pipeline
**Scope**: TEE attestation, identity binding, sealed storage, ECALL boundaries, peer connection security
**CodeQL version**: 2.24.0
**Total SARIF findings**: 171 across 19 queries (11 original + 4 completeness extensions + 4 templates/smoke)

---

## Dashboard Summary

### Finding count by severity and trust-path tier

| Severity  | core | adjacent | peripheral | Total |
|-----------|------|----------|------------|-------|
| Critical  |  0   |    0     |     0      |   0   |
| High      |  2   |    0     |     0      |   2   |
| Medium    |  1   |    0     |     0      |   1   |
| Low       |  0   |    1     |     0      |   1   |
| Info      |  0   |    0     |     0      |   0   |
| **Total** |  **3** |  **1** |     0      |  **4** |

### Total findings count

> Total findings: 4 (Critical: 0, High: 2, Medium: 1, Low: 1, Info: 0)

### Executive risk statement

> The MobileCoin watcher component stores attestation evidence without validating critical fields (quote status, timestamp, debug flag, MRENCLAVE binding), allowing stale or tampered evidence to enter the trust chain. Separately, sealed state has no key rotation support, risking data loss on enclave measurement changes. These two HIGH findings affect the core attestation and sealed storage trust paths respectively.

### Grade history: v1 to v2 transition

| v1 Status | v1 Grade | v2 ID | v2 Severity | Change | Reason |
|-----------|----------|-------|-------------|--------|--------|
| INV-10 hypothesis only | weak | V-01 | HIGH | NEW in v2 | Completeness query found real validation gap |
| INV-08 positive guard | confirmed | V-02 | HIGH | NEW in v2 | Lifecycle dimension: no rotation support |
| INV-14 positive guard | confirmed | V-03 | MEDIUM | NEW in v2 | Lifecycle dimension: rotation doesn't trigger re-attestation |
| INV-03 positive guard | confirmed | V-04 | LOW | NEW in v2 | Lifecycle dimension: hardcoded MRENCLAVE |
| INV-01 positive guard | confirmed | -- | -- | Stable (PG-01) | Confirmed complete in v2 |
| INV-02 positive guard | confirmed | -- | -- | Stable (PG-02) | Field completeness verified |
| INV-04 positive guard | confirmed | -- | -- | Stable (PG-03) | Complete coverage verified |
| INV-09 positive guard | confirmed | -- | -- | Stable (PG-06, PG-07) | Nonce freshness verified |
| INV-12 positive guard | confirmed | -- | -- | Stable (PG-08) | Complete coverage verified |
| INV-13 complex mapping | info | -- | -- | Stable (PG-09) | Fails closed for unknowns |

---

## Severity Rubric

Severity is determined by exploitability × impact × trust-path tier. Full rubric in `references/report-template.md`.

| Severity | Criteria |
|----------|----------|
| **Critical** | Core trust path, directly exploitable, no mitigation. Compromise breaks the TEE's fundamental guarantee. |
| **High** | Core trust path, likely exploitable; or adjacent path with easy exploitation. |
| **Medium** | Adjacent trust path, exploitable under specific conditions; or core path with mitigating factors. |
| **Low** | Peripheral trust path, hard to exploit, or requires unusual deployment. |
| **Info** | Architectural observation, hardening recommendation. No direct exploit. |

## Trust-Path Tier Definitions

| Tier | Definition |
|------|-----------|
| **core** | Directly on the primary trust path. Compromise breaks the TEE guarantee. |
| **adjacent** | Supports the trust path. Compromise weakens but may not directly break the guarantee. |
| **peripheral** | Operational or deployment concern. Compromise impacts availability, not trust. |

---

## Findings

### V-01: Watcher Evidence Stored Without Field-Level Validation

| Field                | Value |
|----------------------|-------|
| **ID**               | V-01 |
| **Severity**         | High |
| **Trust-Path Tier**  | core |
| **Confidence**       | Confirmed issue |
| **Evidence Basis**   | Structural search, manual path trace |
| **Invariant Ref(s)** | INV-10 |

#### Attack Scenario (POC)

1. **Prerequisites**: Attacker can compromise a consensus node OR gain a network position (MITM) between watcher and consensus nodes.
2. **Entry point**: `watcher/src/attestation_evidence_collector.rs:417` — `process_attestation_evidence()` function.
3. **Steps**:
   - Attacker captures valid attestation evidence from time T via network interception or node compromise.
   - Attacker modifies evidence fields: sets `quote_status = GROUP_OUT_OF_DATE` (known vulnerability), changes `report_data` to point to malicious enclave identity, or changes the timestamp to a future time.
   - Modified evidence passes through AKE handshake (channel authentication only, not content validation) at `crypto/ake/enclave/src/lib.rs:212-213`.
   - Evidence reaches `add_attestation_evidence()` at `watcher_db.rs` and is stored without field validation.
   - Watcher subsequently trusts blocks signed by the compromised/stale identity.
4. **Trust boundary crossed**: At the point where evidence enters the watcher database (`attestation_evidence_collector.rs:417`) without content validation, untrusted external data becomes a trusted attestation record.
5. **Impact**: Entire TEE trust chain broken. Watcher accepts blocks from enclaves with known vulnerabilities, debug enclaves, or stale identities. Breaks the attestation guarantee that only valid, fresh, properly-measured enclaves can produce trusted blocks.

#### Code Path

- `watcher/src/attestation_evidence_collector.rs:395-422` — evidence collection and storage entry point
- `watcher/src/attestation_evidence_collector.rs:417` — `add_attestation_evidence()` called without field validation
- `crypto/ake/enclave/src/lib.rs:212-213` — AKE only does deserialization, not content validation

#### What This Means for MobileCoin

MobileCoin uses TEE attestation to ensure that only legitimate consensus enclaves (with correct MRENCLAVE measurements, no debug flags, and valid advisory status) can sign blocks. The watcher is the off-chain component that monitors the blockchain and verifies that block signers have valid attestation evidence. Without field-level validation, the watcher cannot distinguish between evidence from a properly attested enclave and evidence from a compromised, debug, or outdated enclave. This breaks the end-to-end trust guarantee that MobileCoin's blockchain provides — users cannot rely on the attestation chain for transaction integrity.

#### Remediation

- Add field validation in `process_attestation_evidence()` before calling `add_attestation_evidence()`:
  - Call `Verifier::verify()` with appropriate `TrustedIdentity` policy
  - Validate timestamp freshness (e.g., `MAX_EVIDENCE_AGE = 24h`)
  - Check quote status equals `OK`
  - Verify certificate chain to trusted root
  - Enforce debug flag = false in production
  - Validate MRENCLAVE/MRSIGNER against expected measurements
- Reference: MobileCoin's own `DcapVerifier` chain at `attest/verifier/src/dcap.rs:39-57` already implements most of these checks — reuse this verifier for watcher evidence validation.

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v2      | High     | NEW in v2 — discovered by completeness extension query |

---

### V-02: Sealed State Has No Key Rotation Support

| Field                | Value |
|----------------------|-------|
| **ID**               | V-02 |
| **Severity**         | High |
| **Trust-Path Tier**  | core |
| **Confidence**       | Likely issue |
| **Evidence Basis**   | Manual path trace, structural search |
| **Invariant Ref(s)** | INV-08 |

#### Attack Scenario (POC)

1. **Prerequisites**: Enclave binary must be updated (new MRENCLAVE measurement), OR CPU is replaced, OR SGX provisioning key rotates.
2. **Entry point**: `consensus/enclave/impl/src/lib.rs:489` — `unseal_raw()` call during enclave initialization.
3. **Steps**:
   - Operator deploys enclave binary update with security patches (new measurement).
   - SGX sealing key changes because `MRENCLAVE` is different.
   - Enclave attempts to unseal previously sealed private key at `lib.rs:489`: `cached.unseal_raw()?`.
   - `unseal_raw()` returns `Err` because the sealing key no longer matches.
   - Enclave cannot recover its previous signing key, cannot participate in consensus.
   - All sealed state (consensus keys, session data) becomes permanently inaccessible.
4. **Trust boundary crossed**: The SGX sealing boundary itself — the CPU derives a different key after measurement change.
5. **Impact**: Service disruption through data loss. If an attacker can force enclave measurement changes (e.g., via supply chain compromise of build process), they can cause denial of service across all nodes. The `IntelSealed` struct at `attest/core/src/seal.rs` has no version field or migration mechanism.

#### Code Path

- `attest/core/src/seal.rs` — `IntelSealed` struct: opaque blob, no version field
- `consensus/enclave/impl/src/lib.rs:486-491` — unseal on init: `cached.unseal_raw()?`
- `consensus/enclave/impl/src/lib.rs:497` — re-seal: `IntelSealed::seal_raw(key.as_ref(), &[])?`

#### What This Means for MobileCoin

MobileCoin's consensus enclaves seal their private signing keys using Intel SGX's sealing API. This ties sealed data to the enclave's MRENCLAVE measurement. Any binary update (even a security patch) changes the measurement and makes sealed data inaccessible. Without a migration path, operators face a choice between running vulnerable enclave code (security risk) or losing sealed state (availability risk). This is especially critical for a blockchain consensus node where key continuity is essential for network participation.

#### Remediation

- Add a version field to sealed data wrapper around `IntelSealed`
- Implement migration path: before sealing with new key, unseal with old key and re-seal with new key during a controlled transition
- Support multiple active key versions during transition period
- Reference: Intel SGX Sealing documentation recommends application-level key derivation with rotation support

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v1      | N/A (positive guard, flow) | Original audit confirmed flow barrier present |
| v2      | High | NEW lifecycle dimension: no rotation support discovered |

---

### V-03: Fog Key Rotation Does Not Trigger Re-attestation

| Field                | Value |
|----------------------|-------|
| **ID**               | V-03 |
| **Severity**         | Medium |
| **Trust-Path Tier**  | core |
| **Confidence**       | Likely issue |
| **Evidence Basis**   | Manual path trace |
| **Invariant Ref(s)** | INV-14 |

#### Attack Scenario (POC)

1. **Prerequisites**: Fog ingest enclave performs key rotation (regular operational procedure).
2. **Entry point**: `fog/ingest/enclave/impl/src/lib.rs` — key rotation logic.
3. **Steps**:
   - Fog ingest enclave generates new private key during rotation.
   - `current_attestation_evidence` cache at `crypto/ake/enclave/src/lib.rs:625` is NOT cleared.
   - New peer connects and requests attestation evidence.
   - Enclave returns stale cached evidence containing old key binding.
   - Peer verifies evidence against old key identity — verification passes.
   - Connection established with key identity mismatch: peer believes it's talking to the old key's enclave.
4. **Trust boundary crossed**: When stale cached evidence is served to a peer, the peer's trust decision is based on outdated identity information.
5. **Impact**: Attacker who compromises the old key (e.g., through a side-channel attack on the pre-rotation enclave) can continue to impersonate the fog node using the stale attestation evidence. The attestation guarantee that the fog node's current key is properly bound to a measured enclave is weakened.

#### Code Path

- `fog/ingest/enclave/impl/src/lib.rs` — key rotation (RotateKeysError enum)
- `crypto/ake/enclave/src/lib.rs:625` — `current_attestation_evidence` cache not invalidated
- `crypto/ake/enclave/src/lib.rs:636-687` — `new_ereport()` generates fresh attestation but only on demand

#### What This Means for MobileCoin

MobileCoin's fog ingest enclaves handle key rotation for privacy-preserving transaction processing. The attestation evidence binds the enclave's current public key to its MRENCLAVE measurement. When keys rotate without re-attestation, the evidence-key binding becomes stale. While this requires an active rotation event to exploit (mitigating factor), the gap means the attestation system does not provide continuous key-identity assurance. In a Web3 context where fog nodes process sensitive transaction data, stale attestation weakens the privacy guarantee.

#### Remediation

- Clear `current_attestation_evidence` cache on key rotation (set to `None`)
- Force `new_ereport()` call after rotation to generate fresh evidence with new key binding
- Consider explicit rotation protocol where fog nodes notify peers of key changes
- Reject connections with stale evidence older than a configurable threshold

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v1      | N/A (positive guard, binding) | Original audit confirmed key binding present |
| v2      | Medium | NEW lifecycle dimension: rotation gap discovered |

---

### V-04: Hardcoded MRENCLAVE Values Require Recompilation to Update

| Field                | Value |
|----------------------|-------|
| **ID**               | V-04 |
| **Severity**         | Low |
| **Trust-Path Tier**  | adjacent |
| **Confidence**       | Likely issue |
| **Evidence Basis**   | Manual path trace, repo documentation |
| **Invariant Ref(s)** | INV-03 |

#### Attack Scenario (POC)

1. **Prerequisites**: New Intel SGX vulnerability disclosed (e.g., a new advisory not in the hardcoded list).
2. **Entry point**: `consensus/enclave/measurement/src/lib.rs` — `mr_enclave_identity()` function.
3. **Steps**:
   - New Intel advisory (e.g., INTEL-SA-00XXX) published.
   - MobileCoin's hardcoded list only contains INTEL-SA-00334, 00615, 00657.
   - Operator must modify source to add the new advisory to `HARDENING_ADVISORIES`.
   - Recompilation changes MRENCLAVE measurement, triggering V-02 (sealed data loss).
   - All nodes must be redeployed with new binary.
   - Exposure window between advisory disclosure and deployment completion.
4. **Trust boundary crossed**: The trust anchor (MRENCLAVE + advisory list) is static and cannot be updated at runtime.
5. **Impact**: Delayed response to new vulnerabilities. The enclave binary itself cannot be updated to reflect new security requirements without full redeployment. This is an operational risk more than a direct exploit.

#### Code Path

- `consensus/enclave/measurement/src/lib.rs` — `include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))` (compile-time)
- `consensus/enclave/measurement/src/lib.rs` — `HARDENING_ADVISORIES = &["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]`
- `crypto/ake/enclave/src/lib.rs` — `trusted_identity()` uses same hardcoded advisory list

#### What This Means for MobileCoin

MobileCoin's trust anchors are baked into the enclave binary at compile time. While this provides strong integrity guarantees (the measurement cannot be tampered with), it creates operational rigidity. Responding to new Intel advisories requires source code changes, recompilation, and redeployment — a process that can take days or weeks in a production network. This is a standard tradeoff in SGX-based systems, but worth noting for operational planning.

#### Remediation

- Load MRENCLAVE from signed configuration file with hash verification
- Implement runtime trust anchor update mechanism (governance-controlled)
- Consider separating advisory list from MRENCLAVE measurement (advisories in config, measurement in binary)
- Add monitoring for new Intel advisories with automated alerting

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v1      | N/A (positive guard, binding) | Original audit confirmed binding present |
| v2      | Low | NEW lifecycle dimension: no refresh mechanism |

---

## Positive Guards

### PG-01: Attestation Verification Barrier (INV-01)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-01 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | `is_failure()`/`is_err()` barrier blocks unverified attestation evidence from storage. The v2 multi-hop sinks (derive_key, sign, consensus_participate) confirmed no production-code paths bypass the barrier. |
| **Completeness Status** | complete |

#### Code Evidence

- `consensus/enclave/impl/src/lib.rs` — barrier enforcement in attestation verification
- `consensus/enclave/tests/enclave_api_tests.rs:57` — SARIF result: test-only path
- `tests/graceful_teardown.rs:47` — SARIF result: test-only path

---

### PG-02: Report Data Binding Complete (INV-02)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-02 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | `EnclaveReportDataContents` has exactly 3 fields (nonce, key, custom_identity), all required parameters to `new()`. No missing fields. The CodeQL completeness query produced a false positive (matched `MerlinTranscript::new()`). |
| **Completeness Status** | complete |

#### Code Evidence

- `attest/verifier/types/src/convert/enclave_report_data_contents.rs` — struct definition and constructor
- `verification.rs:251-261` — `new()` requires all 3 parameters

---

### PG-03: Debug Attribute Verification Enforced (INV-04)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-03 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | `debug_attribute_verifier(DEBUG_ENCLAVE)` is statically embedded in `DcapVerifier` constructor. Compile-time guaranteed via `And` composition chain. Production builds set `DEBUG_ENCLAVE = false`. All 4 production usages confirmed. |
| **Completeness Status** | complete |

#### Code Evidence

- `attest/verifier/src/dcap.rs:39-57` — `DcapVerifier::new()` with embedded debug check at line 55
- `attest/verifier/src/dcap.rs:63` — wrapper delegates to pre-constructed chain
- `attest/verifier/src/lib.rs:42,49` — `DEBUG_ENCLAVE` compile-time constant

---

### PG-04: SGX Simulation Isolation (INV-05)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-04 |
| **Trust-Path Tier**     | peripheral |
| **What Was Verified**   | Simulation mode flags are config-level gates. Not a live-path vulnerability in production deployments. |
| **Completeness Status** | complete |

---

### PG-05: Sealed Key Unseal Flow Barrier (INV-08 flow)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-05 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | `seal_raw()` barrier is present. Unsealed key material follows expected pattern: unseal -> use inside enclave -> re-seal for storage. No cross-boundary leak. Note: this covers the flow dimension only; the lifecycle dimension (V-02) is a separate finding. |
| **Completeness Status** | partial (flow complete, lifecycle gap in V-02) |

#### Code Evidence

- `consensus/enclave/impl/src/lib.rs:489` — `unseal_raw()` returns key
- `consensus/enclave/impl/src/lib.rs:491` — key used inside enclave only
- `consensus/enclave/impl/src/lib.rs:497` — `seal_raw()` re-encrypts before storage

---

### PG-06: Peer Connection Attestation Barrier (INV-09)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-06 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | All production peer connection paths enforce attestation via AKE state machine. `try_next()` barrier present at both initiator and responder paths. Identity binding to MRENCLAVE correctly implemented. Mock consensus result is test-only. |
| **Completeness Status** | complete |

#### Code Evidence

- `crypto/ake/enclave/src/lib.rs:426` — `responder.try_next()` (accept path)
- `crypto/ake/enclave/src/lib.rs:458` — `initiator.try_next()` (connect path)
- `attest/ake/src/initiator.rs:220-267` — `verify_dcap_evidence()` full verification

---

### PG-07: Nonce Freshness Verified (INV-09 partial)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-07 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Nonce generated with CSPRNG (`QuoteNonce::new(&mut McRng)`). Exact byte-for-byte comparison via `quote_pending.pop(nonce)`, not just presence check. Nonce consumed on verification, preventing replay. LRU cache limits to 64 entries. |
| **Completeness Status** | complete |

#### Code Evidence

- `crypto/ake/enclave/src/lib.rs:642` — CSPRNG nonce generation
- `crypto/ake/enclave/src/lib.rs:680` — `quote_pending.pop(nonce)` exact match
- `crypto/ake/enclave/src/lib.rs:685` — report body comparison

---

### PG-08: ECALL Boundary Validation (INV-12)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-08 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | All ECALL paths through `make_variable_length_ecall` have corresponding `validate()` calls. The completeness query produced 0 results — full coverage confirmed. |
| **Completeness Status** | complete |

---

### PG-09: Advisory Status Handling (INV-13)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-09 |
| **Trust-Path Tier**     | adjacent |
| **What Was Verified**   | All three IAS error types handled in match arms. Unknown advisories rejected (`Err(_) => false`). Production advisory list: INTEL-SA-00334, 00615, 00657. External comparison needed for completeness. |
| **Completeness Status** | complete (code-level), external validation recommended |

#### Code Evidence

- `attest/verifier/src/status.rs:28-57` — match arms for all IAS error types
- `consensus/enclave/measurement/src/lib.rs` — hardcoded advisory list

---

## Agent-Validated Unknowns

None. All items were resolved through self-validation (code reading at SARIF locations).

---

## Appendix: Invariant Cross-Reference Index

### Finding to Invariant

| Finding | Invariant(s) | Type |
|---------|-------------|------|
| V-01 | INV-10 | completeness gap (field validation) |
| V-02 | INV-08 | lifecycle gap (key rotation) |
| V-03 | INV-14 | lifecycle gap (re-attestation) |
| V-04 | INV-03 | lifecycle gap (identity refresh) |
| PG-01 | INV-01 | positive guard |
| PG-02 | INV-02 | positive guard (completeness verified) |
| PG-03 | INV-04 | positive guard (completeness verified) |
| PG-04 | INV-05 | positive guard (config gate) |
| PG-05 | INV-08 | positive guard (flow dimension only) |
| PG-06 | INV-09 | positive guard |
| PG-07 | INV-09 | positive guard (nonce freshness) |
| PG-08 | INV-12 | positive guard (completeness verified) |
| PG-09 | INV-13 | positive guard (with external caveat) |

### Invariant to Finding

| Invariant | Finding(s) | Status |
|-----------|-----------|--------|
| INV-01 | PG-01 | Positive guard, test-only SARIF results |
| INV-02 | PG-02 | Positive guard, completeness verified |
| INV-03 | V-04 | LOW finding: hardcoded MRENCLAVE |
| INV-04 | PG-03 | Positive guard, complete coverage |
| INV-05 | PG-04 | Config-level gate |
| INV-06 | (covered by INV-04) | Compile-time gate |
| INV-07 | (manual, v1) | Hardening gap, not re-audited |
| INV-08 | V-02 + PG-05 | HIGH finding (lifecycle) + positive guard (flow) |
| INV-09 | PG-06 + PG-07 | Positive guard, nonce verified |
| INV-10 | V-01 + PG (flow) | HIGH finding (completeness) + positive guard (flow) |
| INV-11 | (manual, v1) | Needs manual validation, not re-audited |
| INV-12 | PG-08 | Positive guard, complete coverage |
| INV-13 | PG-09 | Positive guard, external validation recommended |
| INV-14 | V-03 | MEDIUM finding: rotation doesn't trigger re-attestation |
