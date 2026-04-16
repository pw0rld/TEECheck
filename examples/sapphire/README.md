# Sapphire (Oasis Paratime) Audit

- **TEE Platform**: Oasis Confidential Runtime
- **Language**: Rust
- **Findings**: 2 (1 High, 1 Medium)
- **Positive Guards**: 8

## Key Findings

| ID | Severity | Title | Invariant |
|----|----------|-------|-----------|
| V-01 | HIGH | Client-side calldata public key not authenticated | INV-07 |
| V-02 | MEDIUM | JS client key cache cross-chain confusion | INV-08 |

V-01 is the most critical finding across all audited projects: a malicious RPC can substitute the client's public key, breaking confidentiality guarantees.

## Files

- `sapphire-paratime-v2-report.md` — Full audit report (SARIF-free deep verification approach)
