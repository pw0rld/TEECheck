# Example Audits

Completed audits of five TEE-enabled Web3 projects, included as worked examples demonstrating the tee-audit pipeline output.

| Project | TEE Platform | Language | Findings | Positive Guards | SARIF |
|---------|-------------|----------|----------|-----------------|-------|
| MobileCoin | SGX (Intel) | Rust | 4 (2H/1M/1L) | 9 | Yes |
| Oasis Core | SGX/TEE (Intel) | Rust/Go | 0 | 7 | Yes |
| Sapphire | Oasis Runtime | Rust | 2 (1H/1M) | 8 | SARIF-free |
| Phala Blockchain | Substrate TEE | Rust | 1 (Info) | 4 | Yes |
| Phala DCAP QVL | SGX/DCAP | Rust | 0 | 8 | Yes |

**Total**: 7 findings (3 High, 1 Medium, 1 Low, 2 Info), 36 positive guards confirmed.

Each directory contains:
- `*-v2-report.md` — Final assembled audit report
- `*.sarif` — SARIF 2.1.0 scan results (where available)
