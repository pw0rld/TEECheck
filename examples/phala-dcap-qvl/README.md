# Phala DCAP QVL Audit

- **TEE Platform**: Intel SGX / DCAP (Data Center Attestation Primitives)
- **Language**: Rust
- **Findings**: 0 confirmed vulnerabilities
- **Positive Guards**: 8

## Positive Guards

Signature verification ordering, PCK cert validation, QE report hash verification, vendor ID check, TCB override gating, attribute dispatch, debug mode rejection.

## Files

- `phala-dcap-qvl-v2-report.md` — Full audit report
- `dcap-qvl-tee-results.sarif` — 11 results, 5 rules (debug-mode-rejection, isv-report-signature-guard, qe-vendor-id-check, tcb-override-feature-gate, tdx-attribute-validation)
