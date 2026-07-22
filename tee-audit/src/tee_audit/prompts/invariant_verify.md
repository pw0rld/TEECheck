# Invariant Verification Against Source Code

You are verifying whether a TEE security invariant is enforced in the codebase. Find concrete evidence of violations or confirm the invariant is upheld.

## Invariant

**ID**: {{invariant_id}}
**Description**: {{invariant_description}}
**Trust Path**: {{invariant_trust_path}}
**Family**: {{invariant_family}}
**Expected Guards**: {{invariant_guards}}
**Failure Modes**: {{invariant_failure_modes}}

## Relevant Source Code

```
{{code_context}}
```

## Instructions

Trace data flow from sources to sinks. Check each guard. Test each failure mode. Look for bypasses (error paths, edge cases, config-dependent behavior).

## False-Positive Discipline

Before reporting a finding, verify it is NOT:

1. **Test code**: Check if the file path contains `test/`, `tests/`, `examples/`, `benches/`, `bin/`,
   or matches test file patterns (`test_*.rs`, `*_test.rs`). Test code is not production attack surface.
2. **Output field misidentification**: In TEE quote verification, `report_data` is an OUTPUT written
   by the enclave, not an input to be validated. The verifier extracts and returns it; the caller
   checks it. Do not report "report_data not verified" as a finding.
3. **Correct API layering**: A low-level verification function that returns parsed fields for the
   caller to check is correct design. Report a finding only if the guard is missing at EVERY layer.

## TEE Domain Knowledge

- **report_data**: Output field in SGX quotes, written by the enclave. Used for key binding.
- **MRENCLAVE/MRSIGNER**: Primary identity mechanism. Verification of these = correct identity check.
- **Collateral (TCB info, CRL, QE identity)**: Fetched from PCCS. Freshness checked via timestamps.
- **Quote verification result**: Returned to caller. Caller decides policy. Verifier is not responsible
  for acting on the result.

## Output Rules — CRITICAL

- **title**: Max 60 chars. No verbs like "Lacks" or "Fails to". Use noun phrases: "Unverified quote signature", "Missing CRL check".
- **attack_path**: Each step = ONE short sentence (max 80 chars). No paragraphs, no explanations.
- **code_locations**: Only file:line pairs where the vulnerability exists.
- **remediation**: 1-2 sentences max. Concrete action, not advice.
- **what_was_checked**: One sentence, max 100 chars.
- **why_uncertain**: One sentence, max 120 chars.
- **recommended_steps**: 1-3 short items, each max 60 chars.
- Prefer making a judgment over marking as unknown. If there is SOME evidence of a guard, report a
  partial positive guard. If there is SOME evidence of a violation, report a Weak/Likely finding.
  Only use "unknown" when there is genuinely zero evidence in either direction.

## Output

If you find a real vulnerability:
```json
{
  "has_finding": true,
  "finding": {
    "invariant_id": "{{invariant_id}}",
    "severity": "Critical|High|Medium|Low|Info",
    "confidence": "Confirmed|Likely|Weak|NeedsManual",
    "title": "<max 8 words, concise label — NOT a description>",
    "attack_path": ["<step 1, max 80 chars>", "<step 2>"],
    "code_locations": [{"file": "<path>", "line": <int>}],
    "remediation": "<1-2 sentences>",
    "cwe_id": "CWE-XXX or null",
    "impact": "<1-2 sentences: what happens if exploited>",
    "root_cause": "<1 sentence: why the vulnerability exists>",
    "preconditions": ["<condition 1>", "<condition 2>"]
  }
}
```

If the invariant is properly enforced:
```json
{
  "has_finding": false,
  "positive_guard": {
    "title": "<concise label, max 8 words, e.g. 'Root CA cert chain validation'>",
    "description": "<what was verified, 1-3 sentences>",
    "code_evidence": "<file:line>",
    "completeness": "complete|partial"
  }
}
```

If you cannot determine with confidence:
```json
{
  "has_finding": false,
  "unknown": {
    "title": "<max 8 words, concise label>",
    "what_was_checked": "<1 sentence, max 100 chars>",
    "why_uncertain": "<1 sentence, max 120 chars>",
    "recommended_steps": ["<step 1, max 60 chars>"]
  }
}
```

Reference exact file paths and line numbers. No speculation without evidence.
