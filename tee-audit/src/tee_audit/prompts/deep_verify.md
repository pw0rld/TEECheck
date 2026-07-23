# Stage 5b: TEE Usage Problem Deep Verification Prompt

You are verifying TEE usage problems in a TEE-enabled Web3 project. For the finding cluster below, perform deep verification focused on TEE trust boundaries and TEE primitive usage.

## Cluster ID: {{cluster_id}}

## TEE Trust Boundary Map

{{fingerprint_map}}

## Trust Zone Classification

{{zone_context}}

## Call Chain Evidence

{{call_chain}}

**Chain Validation Instructions**: The call chain above was traced deterministically from the sink backward through the caller graph. Validate or correct it:
1. For each hop, check if the caller→callee relationship actually exists in the code context provided.
2. If a hop is wrong (e.g., wrong file or function), correct it in your trust_boundary_trace.
3. If the chain is missing intermediate hops visible in the code, add them.
4. If the chain reaches a known entry point (ECALL, RPC handler, HTTP handler), mark confidence as "confirmed".
5. If the chain is incomplete or speculative, note what's missing in trust_boundary_prose.

## Discovered Related Files

{{discovered_files}}

## Code Context

{{code_context}}

## Instructions

For each finding in this cluster:

1. **Read the actual code** at the reported location AND in the discovered related files. Do not rely on the SARIF text alone.
2. **Trace the full TEE attack path** across multiple files with file:line references. Follow the call chain from entry point through trust boundary to sink.
3. **Build a trust boundary trace** — for each finding that IS a TEE usage problem, document the hop-by-hop flow across trust boundaries:
   - source_zone: "trusted" or "untrusted"
   - crossing_point: file:line or function name where the crossing occurs
   - sink_zone: "trusted" or "untrusted"
   - verification_status: "present" (check exists) or "missing" (check absent)
4. **Write prose analysis** — describe in narrative form: what data/control flows across the boundary, what checks exist or are missing, and the impact.
5. **Check for missed TEE-specific guards** the SARIF didn't capture.
6. **Verify completeness** across all four TEE dimensions:
   - Trust boundary: Does the flow cross enclave/host or trusted/untrusted zone?
   - Binding: Are TEE artifacts (measurements, quotes, sealed data) properly bound?
   - Lifecycle: Is the check applied at every TEE state transition?
   - Web3 composability: Can the issue be exploited through cross-chain or cross-service interaction?
7. **Assign severity** using the matrix:

|  | Easily Exploitable | Exploitable | Hard to Exploit |
|---|---|---|---|
| **High Impact** | Critical | High | Medium |
| **Medium Impact** | High | Medium | Low |
| **Low Impact** | Medium | Low | Info |

8. **Write POC** as numbered attack steps. Every finding MUST have a POC.
9. **Attempt self-validation**: If the finding is uncertain, try to resolve it before marking as unknown.

## TEE Relevance Gate — CRITICAL

Before reporting any finding, determine if it is a TEE usage problem:

A finding IS a TEE usage problem if it:
- Involves a TEE primitive directly (attestation, sealing, measurement, ECALL/OCALL, quote generation/verification, key management, freshness), OR
- Affects a trust boundary that TEE is designed to protect (enclave/host boundary, trusted/untrusted zone separation, attestation pipeline integrity)

A finding is NOT a TEE usage problem if it is a generic code bug that does NOT directly undermine a TEE trust boundary:
- Path traversal, shell injection, memory exhaustion without TEE boundary impact
- TLS misconfig on non-TEE-critical endpoints
- DoS via unbounded decode without TEE trust implications
- Missing input validation without trust boundary implications

**If the finding is NOT a TEE usage problem, set `is_tee_relevant: false`.** It will be moved to the appendix.

## False-Positive Discipline — CRITICAL

Before reporting any finding, check these conditions. If ANY apply, do NOT report as a finding:

1. **Test code**: If ALL code locations are in `test/`, `tests/`, `examples/`, `benches/`, `bin/`,
   or files named `test_*.rs`, `*_test.rs`, mark the finding as `dismissed: true` with
   `dismissal_reason: "Test-only code, not production attack surface"`.
2. **Output fields misidentified as inputs**: `report_data` in SGX/TDX quotes is an OUTPUT —
   the enclave writes it during quote generation to bind public keys. The verifier extracts it.
   Findings claiming "report_data should be verified against expected values" are false positives.
3. **Defensive API design**: A low-level function returning parsed fields for the caller to check
   is correct layering, not a vulnerability.
4. **Severity of test code**: If a finding is in test/example code but represents a real pattern,
   downgrade to Info and note it as a best-practice observation.
5. **No end-to-end chain evidence**: If you cannot trace a concrete invocation chain from an attacker-controllable
   entry point (e.g., ECALL parameter, network input, host-provided buffer) through to a security-sensitive
   operation (e.g., key derivation, measurement, attestation output), the finding is speculative. Dismiss it
   with `dismissal_reason: "No verifiable end-to-end invocation chain — speculative scenario"`.
6. **Zone mismatch**: If the vulnerable code runs entirely within the TRUSTED zone (enclave) and the attack
   requires the attacker to control code inside the enclave, dismiss it — that would require breaking the TEE
   itself, which is out of scope. Only report issues where untrusted input crosses into trusted code unchecked,
   or where trusted output leaks to untrusted code without proper binding.
7. **Single-function speculation**: If the finding only examines one function in isolation and the claimed attack
   requires the code execution flow to be interrupted or redirected in a way that does not happen in normal
   operation, dismiss it as speculative. Real vulnerabilities have concrete call chains.

## TEE Domain Knowledge

- **report_data**: 64-byte OUTPUT field the enclave writes. Used for key binding. Verifier extracts
  and returns it; caller checks it. "report_data not verified" is almost always a false positive.
- **MRENCLAVE/MRSIGNER**: Primary identity mechanism. Checking these = correct identity check.
- **Collateral freshness**: TCB info and CRL have `next_update` timestamps. Fetching at
  verification time is correct. Missing CRL check is real only if the path skips CRL entirely.
- **Quote verification result**: Verifier returns structured result. Application decides policy.
  "Result not acted upon" is false positive for the verifier itself.
- **Test/CLI binaries**: Code in `cli/`, `bin/`, `tests/`, `examples/` is NOT attack surface.

## Taxonomy Categories

When a finding IS a TEE usage problem, classify it into one of these categories using the detailed taxonomy reference below. The `tee_category` field must be one of: "Trust Boundary Flow", "Verification Gap", "Binding Weakness", "State Continuity", "Configuration Integrity", "Design Appropriateness", "Output & Metadata Leakage".

{{taxonomy_reference}}

## Finding Format

Each verified finding must have:
- **id**: V-NN format
- **invariant_id**: Link to the parent invariant
- **severity**: Critical, High, Medium, Low, or Info
- **confidence**: Confirmed, Likely, Weak, or NeedsManual
- **title**: Short descriptive title (max 60 chars, noun phrase)
- **attack_path**: Numbered POC steps (list of strings, each max 80 chars)
- **code_locations**: File paths with line numbers
- **remediation**: How to fix it (1-2 sentences)
- **trust_path_tier**: core, adjacent, or peripheral
- **cwe_id**: CWE identifier if applicable (e.g., "CWE-345"), or null
- **impact**: What happens if this vulnerability is exploited (1-2 sentences)
- **root_cause**: Why this vulnerability exists (1 sentence)
- **preconditions**: What must be true for exploitation (list of short strings)
- **tee_category**: One of "Trust Boundary Flow", "Verification Gap", "Binding Weakness", "State Continuity", "Configuration Integrity", "Design Appropriateness", "Output & Metadata Leakage" — or null if is_tee_relevant is false
- **tee_dimension**: One of "incorrect_usage" or "inappropriate_design" — or null if is_tee_relevant is false
- **is_tee_relevant**: true if this is a TEE usage problem, false if it is a generic code bug
- **trust_boundary_trace**: Array of trace hops (only for TEE-relevant findings). Each hop has:
  - source_zone: "trusted" or "untrusted"
  - crossing_point: file:line or function name where data/control crosses
  - sink_zone: "trusted" or "untrusted"
  - verification_status: "present" or "missing"
  - description: brief explanation of what crosses and how
- **trust_boundary_prose**: Narrative analysis of the trust boundary crossing (2-4 sentences). Describe what data/control flows across, what checks exist or are missing, and the impact. Empty string if is_tee_relevant is false.
- **dismissed**: false (default). Set to true if the finding is a false positive per the rules above.
- **dismissal_reason**: Empty string if not dismissed. Otherwise explain why.

## Unknown Format

For findings that cannot be verified:
- **title**: Short concise label (max 8 words, e.g. "Downstream field validation coverage")
- **what_was_checked**: What property was being tested
- **why_uncertain**: Why automated verification could not resolve it
- **recommended_steps**: What manual investigation is needed
- **is_tee_relevant**: true if related to a TEE trust boundary, false otherwise

Respond with a JSON object containing `findings` and `unknowns` arrays.
