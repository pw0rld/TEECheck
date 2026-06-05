# Evidence Grading Reference

## Severity Rubric

| Severity | Definition |
|----------|-----------|
| Critical | Exploitable in production with high impact on funds, keys, or consensus |
| High | Exploitable with moderate effort, significant trust boundary violation |
| Medium | Trust boundary concern requiring specific conditions to exploit |
| Low | Minor hardening issue, defense-in-depth improvement |
| Info | Positive guard, architectural observation, or best-practice note |

## Confidence Grades

| Grade | Definition |
|-------|-----------|
| Confirmed | Code path traced, POC written, guard verified absent |
| Likely | Strong evidence but one step requires assumption |
| Weak | SARIF signal with incomplete code path tracing |
| NeedsManual | Cannot verify without runtime testing or domain expertise |

## Trust-Path Tiers

| Tier | Definition |
|------|-----------|
| core | Directly on the primary trust path (enclave entry, attestation, key management) |
| adjacent | One hop from core path (configuration, build system, deployment scripts) |
| peripheral | Supporting infrastructure (logging, monitoring, documentation) |

## False-Positive Discipline

- If a guard exists in a wrapper or lower-level verifier that IS invoked, mark as Info (positive guard), not a finding
- If the flow exists but the sink is test-only, mark as Info
- If the value is transformed to a safe representation before the sink, mark as Info
- When in doubt, mark as NeedsManual and explain why

## TEE-Specific False-Positive Rules

- **report_data in SGX/TDX quotes**: OUTPUT field, not input. Verifier extracts; caller checks.
  "report_data not verified" is false positive unless the CALLING application also fails to check it.
- **Test/example/benchmark code**: Code in `test/`, `tests/`, `examples/`, `benches/`, `bin/`,
  or files matching `test_*.rs`, `*_test.rs` is NOT production attack surface. Dismiss or mark Info.
- **Low-level API returning structured results**: A function like `verify_quote()` returning a result
  struct is designed for the caller to inspect. Correct layering, not missing validation.
- **CLI output/debug logging**: Debug output in CLI tools or test binaries is expected behavior.
  Only flag if it leaks secrets (private keys, raw attestation keys), not status information.
