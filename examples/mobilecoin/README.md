# MobileCoin Audit

- **TEE Platform**: Intel SGX
- **Language**: Rust
- **Findings**: 4 (2 High, 1 Medium, 1 Low)
- **Positive Guards**: 9

## Key Findings

| ID | Severity | Title | Invariant |
|----|----------|-------|-----------|
| V-01 | HIGH | Watcher evidence stored without field-level validation | INV-10 |
| V-02 | HIGH | Sealed state has no key rotation support | INV-08 |
| V-03 | MEDIUM | Fog key rotation doesn't trigger re-attestation | INV-14 |
| V-04 | LOW | Hardcoded MRENCLAVE identity | INV-03 |

## Files

- `mobilecoin-v2-report.md` — Full audit report
- `mobilecoin-tee-results.sarif` — 111 results across 10 custom TEE invariant rules
