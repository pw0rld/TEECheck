# Phala Blockchain TEE Web3 Security Audit Report v2

**Project**: phala-blockchain
**Audit Date**: 2026-04-16
**Framework**: tee-web3-audit v2 pipeline
**Audit Type**: Static analysis with CodeQL and manual verification

---

## Dashboard Summary

### Finding count by severity and trust-path tier

| Severity  | core | adjacent | peripheral | Total |
|-----------|------|----------|------------|-------|
| Critical  |  0   |    0     |     0      |   0   |
| High      |  0   |    0     |     0      |   0   |
| Medium    |  0   |    0     |     0      |   0   |
| Low       |  0   |    0     |     0      |   0   |
| Info      |  0   |    0     |     1      |   1   |
| **Total** |  0   |    0     |     1      |   1   |

### Total findings count

> Total findings: 1 (Critical: 0, High: 0, Medium: 0, Low: 0, Info: 1)

### Executive risk statement

The Phala blockchain's core TEE attestation path demonstrates strong security posture with confirmed positive guards for report-data binding and freshness enforcement. One Info-level finding regarding PCCS certificate validation represents a deployment configuration choice that does not compromise the core trust path.

### Grade history: v1 to v2 transition

This is a v2 baseline audit. No v1 findings exist for comparison.

---

## Severity Rubric

| Severity    | Criteria |
|-------------|----------|
| **Critical** | Core trust path, directly exploitable, no mitigation required beyond the vulnerability itself. Compromise of the fundamental TEE security guarantee. |
| **High**     | Core trust path, likely exploitable; OR adjacent trust path with straightforward exploitation. |
| **Medium**   | Adjacent trust path, exploitable under specific conditions; OR core trust path with significant mitigating factors already in place. |
| **Low**      | Peripheral trust path, difficult to exploit, or requires an unusual deployment configuration. |
| **Info**     | Architectural observation, hardening recommendation, or configuration best practice. No direct exploitability. |

---

## Trust-Path Tier Definitions

| Tier          | Definition |
|---------------|------------|
| **core**      | Directly on the primary trust path. Compromise breaks the TEE's fundamental security guarantee. |
| **adjacent**  | Supports the trust path. Compromise weakens but may not directly break the guarantee. |
| **peripheral** | Operational or deployment concern. Compromise impacts availability or operations, not the trust guarantee itself. |

---

## Findings

### V-01: DCAP PCCS server accepts invalid TLS certificates

| Field                | Value |
|----------------------|-------|
| **ID**               | V-01 |
| **Severity**         | Info |
| **Trust-Path Tier**  | peripheral |
| **Confidence**       | high |
| **Evidence Basis**   | CodeQL + manual code review |
| **Invariant Ref(s)** | INV-05 |

#### Attack Scenario (POC)

1. **Prerequisites**: An attacker controls a PCCS server or can intercept traffic between the TEE enclave and a legitimate PCCS server.
2. **Entry point**: The enclave calls `create_attestation_report()` or `get_collateral()` with a PCCS server URL.
3. **Steps**:
   - Enclave prepares to fetch DCAP collateral from PCCS server (`crates/sgx-attestation/src/dcap/report.rs:30-34`)
   - HTTP client is configured with `danger_accept_invalid_certs(true)` at line 31
   - Enclave makes HTTP requests to PCCS server without validating TLS certificate chain
   - Attacker can present self-signed or fraudulent TLS certificates
4. **Trust boundary crossed**: None. The attestation validation itself is not compromised. The PCCS collateral is still cryptographically verified through the DCAP verification chain.
5. **Impact**: Potential for MITM attacks on PCCS server communication. However, the overall attestation chain remains secure because:
   - The quote signature is verified independently
   - The collateral integrity is checked
   - The trust root is the Intel PCK certificate chain, not the TLS connection

#### Code Path

- `crates/sgx-attestation/src/dcap/report.rs:31` -- HTTP client configured to accept invalid certs
- `crates/sgx-attestation/src/dcap/report.rs:30-34` -- Client creation in `get_collateral()`
- `crates/sgx-attestation/src/dcap/report.rs:118-119` -- Collateral fetch in `create_attestation_report()`

#### What This Means for Phala Blockchain

Phala Blockchain uses TEE enclaves to secure confidential computing and provide attestation for worker nodes. The DCAP PCCS certificate validation issue is a peripheral concern because:

1. **Core trust path remains intact**: The attestation validation chain (quote signature verification, collateral integrity checks, TCB status validation) does not rely on TLS certificate validation for security.
2. **PCCS is a trusted service**: In production deployments, PCCS servers are operated by Intel or trusted cloud providers, making TLS certificate validation less critical.
3. **Configuration flexibility**: This design allows Phala to deploy against self-hosted or custom PCCS instances with self-signed certificates, which is a valid deployment scenario.

The security of the overall attestation system depends on the DCAP cryptographic verification chain, not the TLS connection to the PCCS server.

#### Remediation

**Recommended actions**:

1. **Document the security rationale**: Add inline documentation explaining why `danger_accept_invalid_certs(true)` is used and why it's acceptable in this context.

2. **Make certificate validation configurable**: Add a compile-time feature flag or runtime configuration option to enable strict TLS certificate validation for production deployments:
   ```rust
   #[cfg(feature = "strict_tls_validation")]
   let builder = reqwest::Client::builder();
   #[cfg(not(feature = "strict_tls_validation"))]
   let builder = reqwest::Client::builder()
       .danger_accept_invalid_certs(true);
   ```

3. **Add logging**: Log when PCCS server is contacted without TLS validation to aid in security monitoring.

4. **Deployment guidance**: Update operational documentation to recommend using official Intel PCCS servers or properly configured PCCS servers with valid TLS certificates.

**Reference**: Intel SGX DCAP attestation flow documentation, RFC 2818 (HTTP over TLS), OWASP A02:2021 - Cryptographic Failures.

#### V1 to V2 Grade History

| Version | Severity | Notes |
|---------|----------|-------|
| v2      | Info     | NEW in v2 |

---

## Positive Guards

### PG-01: Report-data binding verification in modern attestation

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-01 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Attestation report_data field is cryptographically bound to expected user_data_hash, preventing tampering with committed data |
| **Completeness Status** | complete |

#### Code Evidence

- `pallets/phala/src/utils/attestation.rs:131-136` -- User data hash validation
- `pallets/phala/src/utils/attestation.rs:286` -- Report data extraction from IAS quote

#### Verification Details

The code explicitly verifies that the first 32 bytes of `report_data` from the attestation match the expected `user_data_hash`. If they don't match, the attestation is rejected with `Error::InvalidUserDataHash`. This prevents attackers from tampering with the data committed to in the TEE report.

### PG-02: Report-data binding verification in legacy attestation

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-02 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Legacy attestation path maintains the same report-data binding verification as modern implementation |
| **Completeness Status** | complete |

#### Code Evidence

- `pallets/phala/src/utils/attestation_legacy.rs:192-195` -- User data hash validation
- `pallets/phala/src/utils/attestation_legacy.rs:90` -- Report data extraction from IAS quote

#### Verification Details

The legacy attestation implementation uses identical binding verification logic, ensuring backward compatibility without security regression.

### PG-03: Report freshness enforcement in modern attestation

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-03 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Attestation reports are rejected if older than 7200 seconds (2 hours), preventing replay attacks |
| **Completeness Status** | complete |

#### Code Evidence

- `pallets/phala/src/utils/attestation.rs:168-170` -- Freshness window check
- `pallets/phala/src/utils/attestation.rs:49` -- Timestamp extraction from IAS report

#### Verification Details

The code calculates `now - report_timestamp` and rejects any report where the difference is >= 7200 seconds. This prevents attackers from replaying old, valid attestations that may have been generated before a security update or key rotation.

### PG-04: Report freshness enforcement in legacy attestation

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-04 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Legacy attestation path maintains the same 7200-second freshness window enforcement |
| **Completeness Status** | complete |

#### Code Evidence

- `pallets/phala/src/utils/attestation_legacy.rs:188-190` -- Freshness window check
- `pallets/phala/src/utils/attestation_legacy.rs:46` -- Timestamp extraction from IAS report

#### Verification Details

The legacy implementation uses the same freshness window logic, ensuring consistent security guarantees across both attestation versions.

---

## Agent-Validated Unknowns

None. All invariants that could be verified through static analysis have been resolved.

---

## Appendix: Invariant Cross-Reference Index

### Finding ID to Invariant ID Mapping

| Finding ID | Invariant Ref(s) |
|------------|------------------|
| V-01       | INV-05           |

### Invariant ID to Finding ID Mapping

| Invariant ID | Finding ID | Status |
|--------------|------------|--------|
| INV-01       | --         | Positive Guard (PG-01, PG-02) |
| INV-02       | --         | Not triggered in baseline |
| INV-03       | --         | Positive Guard (PG-03, PG-04) |
| INV-04       | --         | Not triggered in baseline |
| INV-05       | V-01       | Info finding |
| INV-07       | --         | Not triggered in baseline |
| INV-08       | --         | No finding |
| INV-11       | --         | Not applicable (different architecture) |

---

## Methodology

This audit was conducted using the tee-web3-audit v2 pipeline, which combines:

1. **CodeQL static analysis**: 7 queries across 8 invariants targeting TEE-specific security properties
2. **Expressibility analysis**: Classification of which invariants can be verified through static analysis vs. requiring manual verification
3. **Deep verification**: Manual code review of all SARIF findings and additional invariant checks
4. **Evidence grading**: Systematic classification of findings by severity, confidence, and trust-path tier

### CodeQL Query Coverage

- **Multi-hop taint analysis**: Traced data flow for identity keys, user data hashes, and master keys
- **Structural co-occurrence**: Verified presence of required fields and validation patterns
- **Temporal analysis**: Identified timestamp access points for freshness verification
- **Web3 composability**: Traced attestation flows through on-chain pallet storage and state transitions

### Verification Protocol

For each SARIF cluster:
1. Read ±50 lines of source code around the finding location
2. Analyze the security property being verified
3. Check for lower-layer guards, wrapper functions, and conditional compilation
4. Build attack paths for confirmed issues
5. Assign severity and trust-path tier
6. Create POC scenarios

---

## Conclusion

The Phala blockchain demonstrates strong security posture in its core TEE attestation implementation. All critical trust-path invariants (report-data binding, freshness enforcement) are properly implemented with positive guards confirmed through both CodeQL analysis and manual verification. The single Info-level finding represents a deployment configuration choice that does not compromise the fundamental security guarantees of the attestation system.

**Recommendations for future audits**:

1. Consider adding CodeQL queries to verify PRuntime hash allowlist enforcement
2. Extend multi-hop taint analysis to trace identity key usage through consensus participation
3. Monitor for changes in DCAP PCCS certificate validation as the ecosystem evolves

---

**Report generated by**: tee-web3-audit v2 pipeline
**Generated**: 2026-04-16
**Framework version**: 2.0.0
**CodeQL version**: 2.24.0
