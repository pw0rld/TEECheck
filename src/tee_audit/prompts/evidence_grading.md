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
