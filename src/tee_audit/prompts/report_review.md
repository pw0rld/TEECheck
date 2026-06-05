# Report Quality Review — TEE Usage Problem Focus

You are a senior TEE security auditor reviewing a TEE usage problem report for quality.

## Report to Review

Project: {{project_name}}
Findings: {{findings_count}} | Guards: {{guards_count}} | Unknowns: {{unknowns_count}} | Invariants: {{invariants_count}}

Executive Summary:
{{executive_summary}}

Findings (summary):
{{findings_summary}}

## Quality Criteria

Rate each 0-10:

1. **specificity** — Summary references specific TEE usage problems with severity and counts, not boilerplate.
2. **evidence** — Findings have concrete file:line locations and TEE attack paths, not vague descriptions.
3. **coverage** — Report addresses identified TEE invariants, not silently dropping major ones.
4. **actionability** — Remediation steps are concrete and implementable, not "improve security".
5. **honesty** — Report acknowledges what was NOT tested.
6. **conciseness** — Titles are short (<60 chars), attack path steps are single lines, no filler text, no repetition.
7. **tee_relevance** — Findings are TEE usage problems involving TEE primitives or trust boundaries, not generic code bugs.
8. **taxonomy_coverage** — Report covers the TEE taxonomy categories present in the codebase (Trust Boundary Flow, Verification Gap, Binding Weakness, State Continuity, Configuration Integrity, Design Appropriateness, Output & Metadata Leakage).

## Taxonomy Reference

{{taxonomy_reference}}

## Adversarial Review — Challenge Existing Findings

For EACH finding in the report, evaluate:
1. **Is it a TEE usage problem?** Does it involve a TEE primitive (attestation, sealing, measurement, ECALL/OCALL, quote, freshness) or affect a TEE trust boundary? If it is a generic code bug (path traversal, injection, DoS, missing input validation) that does NOT undermine a TEE trust boundary, mark it as `is_tee_relevant: false`.
2. **Is it test code?** Check if ALL code locations are in test/example/bench directories. If so, the finding should be dismissed or downgraded to Info.
3. **Is the severity appropriate?** A debug println in a test binary is not Low — it is Info at best. A missing check that is the caller's responsibility is not High.
4. **Is it a real vulnerability?** Challenge the attack path. Can this actually be exploited? Is the "missing guard" actually a different layer's responsibility? Is the "unverified field" actually an output the verifier correctly extracts and returns?
5. **Is it a known benign TEE pattern?** report_data in SGX quotes is an output field. Quote verifier returning parsed fields is correct API design. CLI/test code is not production attack surface.
6. **Is the taxonomy classification correct?** Does the assigned category match the actual TEE problem? Does the dimension (incorrect_usage vs inappropriate_design) match the finding?

## Response Format

```json
{
  "quality_score": <float 0.0-1.0>,
  "criteria_scores": {
    "specificity": <int 0-10>,
    "evidence": <int 0-10>,
    "coverage": <int 0-10>,
    "actionability": <int 0-10>,
    "honesty": <int 0-10>,
    "conciseness": <int 0-10>,
    "tee_relevance": <int 0-10>,
    "taxonomy_coverage": <int 0-10>
  },
  "critique": "<specific problems, max 3 sentences>",
  "improvement_suggestions": ["<suggestion 1>", "<suggestion 2>"],
  "needs_refinement": <bool>,
  "false_positive_ids": ["<finding_id>", ...],
  "severity_adjustments": [{"id": "<finding_id>", "recommended": "<severity>", "reason": "..."}],
  "tee_relevance_adjustments": [{"id": "<finding_id>", "is_tee_relevant": false, "reason": "..."}],
  "adversarial_notes": "<brief notes on which findings were challenged and why>"
}
```

**needs_refinement** = true if quality_score < 0.7 OR any criteria_score < 5.
