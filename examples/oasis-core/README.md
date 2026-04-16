# Oasis Core Audit

- **TEE Platform**: Intel SGX / TEE Runtime
- **Language**: Rust, Go
- **Findings**: 0 confirmed vulnerabilities
- **Positive Guards**: 7

## Positive Guards

MRENCLAVE matching, TCB status verification, timestamp freshness, debug rejection, RAK binding, unsafe build flag detection, QE identity verification.

## Design Decisions

- DD-01: SW_HARDENING_NEEDED acceptance documented as explicit trade-off

## Files

- `oasis-core-v2-report.md` — Full audit report
- `oasis-core-tee-results.sarif` — 2 results, 1 rule (tcb-level-acceptance)
