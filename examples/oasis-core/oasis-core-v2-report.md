# Oasis Core TEE Web3 Audit Report (v2)

**Framework**: tee-web3-audit v2 pipeline
**Generated**: 2026-04-16
**SARIF**: `/tmp/oasis-core-v2-baseline.sarif`
**Project**: oasis-core
**Auditor**: Claude (tee-web3-audit agent)

---

## Dashboard Summary

### Finding count by severity and trust-path tier

| Severity  | core | adjacent | peripheral | Total |
|-----------|------|----------|------------|-------|
| Critical  |  0   |    0     |     0      |   0   |
| High      |  0   |    0     |     0      |   0   |
| Medium    |  0   |    0     |     0      |   0   |
| Low       |  0   |    0     |     0      |   0   |
| Info      |  0   |    0     |     0      |   0   |
| **Total** |  0   |    0     |     0      |   0   |

### Total findings count

> Total findings: 0 (Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0)

### Executive risk statement

> Oasis Core's TEE attestation implementation demonstrates strong security posture with no confirmed vulnerabilities. All 16 SARIF results from the v2 baseline are false positives resulting from CodeQL capturing field access in data extraction functions rather than verification sites. The core trust path (MRENCLAVE verification, TCB status checking, timestamp validation, and identity binding) is properly enforced with explicit guards. One design decision—accepting `SW_HARDENING_NEEDED` TCB status—is intentional per project history but should be documented in security materials.

### Grade history: v1 to v2 transition

This is the first v2 audit for Oasis Core. No v1 findings exist for comparison.

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

**No findings identified.** All 16 SARIF results were determined to be false positives through deep code verification.

---

## Positive Guards

### PG-01: MRENCLAVE/MRSIGNER identity verification

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-01 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Quote MRENCLAVE and MRSIGNER are compared against the local enclave's identity before acceptance |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/identity.rs:284-289` -- Explicit comparison of `verified_quote.identity.mr_enclave` against local enclave
- `runtime/src/identity.rs:284-289` -- Explicit comparison of `verified_quote.identity.mr_signer` against local enclave
- `runtime/src/common/sgx/ias.rs:338-343` -- MRENCLAVE/MRSIGNER extraction into VerifiedQuote struct
- `runtime/src/common/sgx/pcs/quote.rs:409-414` -- PCS path extraction into EnclaveIdentity

#### Verification Flow

The verification occurs in `identity.rs:284-289` within the `set_quote()` method:

```rust
// Verify that the quote's enclave identity matches our own.
let enclave_identity = inner
    .enclave_identity
    .as_ref()
    .expect("Enclave identity must be configured");
if verified_quote.identity.mr_enclave != enclave_identity.mr_enclave {
    return Err(QuoteError::MrEnclaveMismatch.into());
}
if verified_quote.identity.mr_signer != enclave_identity.mr_signer {
    return Err(QuoteError::MrSignerMismatch.into());
}
```

This guard ensures that only enclaves with the exact expected MRENCLAVE and MRSIGNER can provide acceptable quotes.

---

### PG-02: TCB status acceptance/rejection logic

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-02 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | TCB status is explicitly checked with acceptance/rejection logic for all status levels |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/common/sgx/ias.rs:277-294` -- Explicit match statement on TCB status with rejection logic
- `runtime/src/common/sgx/pcs/tcb.rs:662-671` -- TCB level verification with UpToDate check

#### Acceptance Policy

The IAS path accepts:
- `"OK"` - TCB is up to date
- `"SW_HARDENING_NEEDED"` - TCB has known vulnerabilities with software mitigations

The IAS path rejects (unless `OASIS_UNSAFE_LAX_AVR_VERIFY` is set):
- `"GROUP_OUT_OF_DATE"`, `"CONFIGURATION_NEEDED"`, `"CONFIGURATION_AND_SW_HARDENING_NEEDED"` - Require TCB updates
- Any other status (including `"OUT_OF_DATE"`, `"REVOKED"`)

The PCS path enforces:
- TCB status must be `UpToDate` (verified at `tcb.rs:666-668`)

---

### PG-03: Timestamp freshness validation

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-03 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | AVR/quote timestamps are validated against a 24-hour freshness window |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/common/sgx/ias.rs:516-518` -- Timestamp freshness function definition
- `runtime/src/common/sgx/ias.rs:273-275` -- Freshness check before AVR acceptance
- `runtime/src/common/sgx/mod.rs:85` -- Clock ratchet using verified timestamp

#### Freshness Window

```rust
pub(crate) fn timestamp_is_fresh(now: i64, timestamp: i64) -> bool {
    (now - timestamp).abs() < 60 * 60 * 24  // 24 hours
}
```

The 24-hour window allows for reasonable quote caching while preventing acceptance of stale attestation reports.

---

### PG-04: Debug enclave rejection

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-04 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Debug enclaves are rejected in production environments |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/common/sgx/ias.rs:317-327` -- Debug flag detection and rejection logic
- `runtime/src/common/sgx/pcs/quote.rs:101-106` -- PCS path debug enclave check

#### Verification Logic

```rust
let is_debug = quote_body
    .report_body
    .attributes
    .flags
    .contains(AttributesFlags::DEBUG);
let allow_debug = option_env!("OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES").is_some();
if is_debug && !allow_debug {
    return Err(AVRError::DebugEnclave.into());
}
```

This ensures that debug enclaves (which lack hardware-enforced confidentiality) cannot participate in production attestation unless explicitly allowed via compile-time flag.

---

### PG-05: RAK binding verification

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-05 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | The Runtime Attestation Key (RAK) hash is cryptographically bound to the quote's report data |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/identity.rs:292` -- RAK binding verification call
- `runtime/src/identity.rs:274` -- Nonce extraction from report data

#### Verification Flow

The `verify_binding()` method ensures that the RAK public key hash is present in the quote's report data, binding the attestation key to the specific enclave instance. This prevents quote replay attacks and key substitution.

---

### PG-06: Unsafe build flag gating

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-06 |
| **Trust-Path Tier**     | peripheral |
| **What Was Verified**   | All unsafe build flags are properly gated at compile time and disable the `is_secure` flag |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/lib.rs:79-120` -- Compile-time flag checking and `maybe_secure` flag management
- `runtime/src/common/sgx/ias.rs:252-253` -- IAS unsafe flag usage
- `runtime/src/common/sgx/pcs/quote.rs:46-47, 102` -- PCS unsafe flag usage

#### Gated Flags

- `OASIS_UNSAFE_SKIP_AVR_VERIFY` - Skips IAS/PCS signature verification
- `OASIS_UNSAFE_LAX_AVR_VERIFY` - Accepts GROUP_OUT_OF_DATE, CONFIGURATION_NEEDED
- `OASIS_UNSAFE_ALLOW_DEBUG_ENCLAVES` - Allows debug enclaves in production

All flags are checked with `option_env!` at compile time and properly set `BUILD_INFO.is_secure = false` when present.

---

### PG-07: QE identity verification (PCS path)

| Field                   | Value |
|-------------------------|-------|
| **ID**                  | PG-07 |
| **Trust-Path Tier**     | core |
| **What Was Verified**   | Quoting Enclave identity is verified against TCB info for PCS quotes |
| **Completeness Status** | complete |

#### Code Evidence

- `runtime/src/common/sgx/pcs/tcb.rs:580-671` -- QE identity verification function
- `runtime/src/common/sgx/pcs/tcb.rs:587-589` -- MRSIGNER verification
- `runtime/src/common/sgx/pcs/tcb.rs:593-595` -- ISVPRODID verification
- `runtime/src/common/sgx/pcs/tcb.rs:666-668` -- TCB status UpToDate check

#### Verification Flow

The `QEIdentity::verify()` method ensures:
1. QE MRSIGNER matches the expected value from TCB info
2. QE ISVPRODID matches the expected value from TCB info
3. QE MISCSELECT and XFRM attributes match masked expected values
4. QE TCB status is UpToDate based on ISVSVN comparison

This prevents attackers from using compromised or outdated quoting enclaves.

---

## Agent-Validated Unknowns

**None** - All items investigated during Stage 5b were successfully resolved through code review and documentation analysis.

---

## Design Decisions Requiring Documentation

### DD-01: SW_HARDENING_NEEDED TCB Status Acceptance

| Field | Value |
|-------|-------|
| **ID** | DD-01 |
| **What** | Intentional acceptance of `SW_HARDENING_NEEDED` TCB status in attestation verification |
| **Location** | `runtime/src/common/sgx/ias.rs:279` |
| **Rationale** | Per CHANGELOG, this allows enclaves with software-mitigatable TCB issues to participate, reducing network downtime while waiting for full TCB recovery |

#### Context

Intel SGX TCB status `SW_HARDENING_NEEDED` indicates that the platform has known vulnerabilities that can be mitigated through software patches rather than requiring a platform firmware update. Oasis Core intentionally accepts this status to balance security with operational continuity.

#### Current Implementation

```rust
match quote_status.as_str() {
    "OK" | "SW_HARDENING_NEEDED" => {}
    // ... other statuses rejected
}
```

#### Advisory ID Availability

The AVR includes advisory IDs for `SW_HARDENING_NEEDED` status (verified in test data at `ias.rs:624-634`), allowing operators to monitor which specific TCB issues are present. However, the production code does not currently log these IDs on acceptance.

#### Recommendation

Document this decision in the security model (`docs/SECURITY.md`) explaining:
1. Why `SW_HARDENING_NEEDED` is acceptable for Oasis Core's threat model
2. How operators should monitor advisory IDs (consider adding logging)
3. When to consider rejecting `SW_HARDENING_NEEDED` quotes (e.g., for high-value validators)

---

## Appendix: Full Invariant Cross-Reference

### Finding to Invariant Mapping

No findings exist, so no mapping is needed.

### Invariant to Finding/Possible Guard Mapping

| Invariant | Status | Related Guard(s) | Notes |
|-----------|--------|------------------|-------|
| INV-01 (RAK binding) | Verified | PG-05 | RAK hash bound to quote report data |
| INV-02 (MRENCLAVE matching) | Verified | PG-01 | Explicit comparison at identity.rs:284-289 |
| INV-03 (Nonce freshness) | Not applicable | - | Not applicable to oasis-core architecture |
| INV-04 (Debug enclave rejection) | Verified | PG-04 | Debug flag detection and rejection |
| INV-07 (TCB level acceptance) | Verified | PG-02 | Explicit match statement with guards |
| INV-08 (Timestamp validation) | Verified | PG-03 | 24-hour freshness window |
| INV-11 (Unsafe build flags) | Verified | PG-06 | Compile-time gating present |
| INV-12 (RAK private key usage) | Not in scope | - | Key usage patterns not in audit scope |

### CodeQL False Positive Analysis

| Rule ID | False Positive Count | Root Cause |
|---------|---------------------|------------|
| `oasis-core/mrenclave-matching-completeness` | 12 | Captured field access in data extraction/construction functions rather than verification sites |
| `oasis-core/tcb-level-acceptance` | 2 | CodeQL query did not recognize the match statement as a guard |
| `oasis-core/tcb-level-acceptance-completeness` | 2 | Duplicate of above |

### SARIF Result Breakdown

| Cluster | Rule | File | Lines | Count | Resolution |
|---------|------|------|-------|-------|------------|
| 1 | INV-02 completeness | runtime/src/common/sgx/ias.rs | 341-342 | 2 | PG-01 (verification at identity.rs) |
| 2 | INV-02 completeness | runtime/src/common/sgx/mod.rs | 34-35, 137-138 | 4 | Test-only mock code |
| 3 | INV-02 completeness | runtime/src/common/sgx/pcs/quote.rs | 410-411 | 2 | PG-01 (verification at identity.rs) |
| 4 | INV-02 completeness | runtime/src/common/sgx/pcs/tcb.rs | 583, 587, 593, 663 | 4 | PG-07 (guards in same function) |
| 5 | INV-07 completeness | runtime/src/common/sgx/ias.rs | 280 | 2 | PG-02 + DD-01 |
| 6 | INV-07 acceptance | runtime/src/common/sgx/ias.rs | 280 | 2 | PG-02 (duplicate of cluster 5) |

---

## Verification Methodology

### Stage 5a: Quick Triage

- Parsed 16 SARIF results from baseline
- Clustered by (invariant_id, file) pairs into 6 clusters
- Applied initial grading based on code context

### Stage 5b: Deep Verification

- Read actual source code at each SARIF location (±50 lines)
- Traced data flow from extraction to verification sites
- Verified guard co-occurrence for TCB status checks
- Reviewed project documentation and CHANGELOG for design rationale
- Confirmed all INV-02 findings verify at `identity.rs:284-289`
- Confirmed all INV-07 findings have explicit match statement guards
- Identified DD-01 as intentional design decision per project history

### Stage 6: Report Assembly

- Assembled v2 report using template structure
- Documented 7 positive guards with code evidence
- Identified 1 design decision requiring documentation
- Provided full invariant cross-reference
- Analyzed CodeQL false positive root causes

---

## Conclusion

Oasis Core's TEE attestation implementation demonstrates a strong security posture with no confirmed vulnerabilities. The codebase properly implements all core invariants:

1. **Identity verification** (INV-02): MRENCLAVE and MRSIGNER are explicitly compared against local enclave identity
2. **TCB status checking** (INV-07): Explicit acceptance/rejection logic for all status levels
3. **Timestamp validation** (INV-08): 24-hour freshness window enforced
4. **Debug enclave rejection** (INV-04): Debug enclaves rejected in production
5. **RAK binding** (INV-01): RAK hash bound to quote report data
6. **Unsafe flag gating** (INV-11): All unsafe flags compile-time guarded
7. **QE identity verification** (PCS): Comprehensive QE identity checks against TCB info

The 16 SARIF results are all false positives resulting from CodeQL capturing field access in data extraction functions rather than verification sites. One design decision—accepting `SW_HARDENING_NEEDED` TCB status—is intentional per project history but should be documented in security materials.

**Recommendation**: Document DD-01 (SW_HARDENING_NEEDED acceptance) in security documentation and consider adding advisory ID logging for operational monitoring.

---

## Files Analyzed

- `runtime/src/common/sgx/ias.rs` (709 lines)
- `runtime/src/common/sgx/mod.rs` (149 lines)
- `runtime/src/common/sgx/pcs/quote.rs` (947 lines)
- `runtime/src/common/sgx/pcs/tcb.rs` (808 lines)
- `runtime/src/identity.rs` (410 lines)
- `runtime/src/common/time.rs` (74 lines)
- `runtime/src/lib.rs` (unsafe flag handling)
- `docs/SECURITY.md`
- `CHANGELOG.md`
