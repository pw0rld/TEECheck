---
name: tee-usage-audit
description: Use when auditing a repository for TEE usage vulnerabilities, especially when a GitNexus knowledge pack is available and the goal is to find trust-boundary violations, missing verification, missing binding, or insecure fallback logic.
---

# TEE Usage Audit

Use this skill when the task is to review a codebase for mistakes that weaken trusted execution assumptions.

## Inputs

Prefer this order:

1. `reports/knowledge-pack.md`
2. `reports/knowledge-pack.json` if available
3. raw source files for the top hotspots

Treat the knowledge pack as compressed structure. Always verify suspicious claims against real code before calling them findings.

## Focus

Look for missing or weak obligations around:

- trust-boundary revalidation
- attestation or identity verification
- session, caller, handle, object, or key binding
- authorization before sensitive commands
- state transitions before privileged operations
- freshness, nonce, rollback, or version enforcement
- secure failure behavior

Read [references/obligations.md](references/obligations.md) when you need the detailed checklist.

## Workflow

1. Read the knowledge pack overview, relevant files, relevant symbols, and audit questions.
2. Build a short trust-boundary map from the hotspots.
3. Inspect the top 3 to 8 hotspot files or symbols in the real source.
4. For each suspicious path, ask which obligation should hold before trust is granted or a sensitive operation happens.
5. Classify each result as `confirmed_candidate`, `likely_issue`, or `needs_review`.
6. Cite exact files and lines whenever possible.

## Output Discipline

- Prefer a short, ranked candidate list.
- Be conservative when evidence is partial.
- Explain why the issue matters to the TEE trust model, not just to general code quality.
- Note strong safe patterns if they materially reduce risk.

## Do Not

- Do not treat graph hotspots as proof of a bug.
- Do not report generic style issues.
- Do not assume checks done outside the trusted boundary are sufficient.
- Do not overstate confidence when wrappers, helpers, or multiple backends obscure the trust decision.
