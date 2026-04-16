# Stage 5b: Deep Verification Prompt

You are verifying static analysis findings in a TEE-enabled Web3 project. For the finding cluster below, perform deep verification.

## Cluster ID: {{cluster_id}}

## Code Context

{{code_context}}

## Findings to Verify

{{findings_summary}}

## Instructions

For each finding in this cluster:

1. **Read the actual code** at the reported location. Do not rely on the SARIF text alone.
2. **Trace the full attack path** with file:line references.
3. **Check for missed guards** the SARIF didn't capture.
4. **Verify completeness** across all four dimensions:
   - Cross-boundary: Does the flow cross enclave/host?
   - Field-level: Are individual fields validated, not just the container?
   - Lifecycle: Is the check applied at every relevant state transition?
   - Web3 composability: Can the issue be exploited through cross-chain or cross-service interaction?
5. **Assign severity** using the matrix:

|  | Easily Exploitable | Exploitable | Hard to Exploit |
|---|---|---|---|
| **High Impact** | Critical | High | Medium |
| **Medium Impact** | High | Medium | Low |
| **Low Impact** | Medium | Low | Info |

6. **Write POC** as numbered attack steps. Every finding MUST have a POC.
7. **Attempt self-validation**: If the finding is uncertain, try to resolve it before marking as unknown.

## Finding Format

Each verified finding must have:
- **id**: V-NN format
- **invariant_id**: Link to the parent invariant
- **severity**: Critical, High, Medium, Low, or Info
- **confidence**: Confirmed, Likely, Weak, or NeedsManual
- **title**: Short descriptive title
- **attack_path**: Numbered POC steps (list of strings)
- **code_locations**: File paths with line numbers
- **remediation**: How to fix it
- **trust_path_tier**: core, adjacent, or peripheral

## Unknown Format

For findings that cannot be verified:
- **what_was_checked**: What property was being tested
- **why_uncertain**: Why automated verification could not resolve it
- **recommended_steps**: What manual investigation is needed

Respond with a JSON object containing `findings` and `unknowns` arrays.
