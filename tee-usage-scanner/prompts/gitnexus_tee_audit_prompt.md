# GitNexus TEE Audit Prompt

Use this template when you want Codex or another LLM to audit a repository with:

- a GitNexus-derived knowledge pack
- a TEE usage audit skill
- local access to the repository files

## Inputs

Provide the model with:

1. `reports/knowledge-pack.md`
2. `reports/knowledge-pack.json` if available
3. `skills/tee-usage-audit/SKILL.md`
4. the repository itself so the model can open cited files

## Prompt Template

```md
You are auditing a repository for TEE usage vulnerabilities.

Read these inputs first:
- the knowledge pack markdown
- the TEE usage audit skill
- the knowledge pack JSON if it is available

Treat the knowledge pack as compressed repository context, not as a vulnerability verdict.
Use the TEE skill as the obligation model.

Your task:
1. Build a short trust-boundary map for the repository.
2. Identify the 3 to 8 most important files or symbols to inspect first.
3. Inspect the cited hotspots in the actual source code.
4. Report only issues that could weaken trusted execution assumptions, attestation guarantees, key protection, session binding, authorization, freshness, or failure handling.
5. Be conservative. If evidence is incomplete, say `needs_review` instead of claiming a confirmed bug.

Audit priorities:
- revalidation of untrusted inputs inside the trusted boundary
- attestation or identity verification completeness
- session, handle, caller, or key binding
- state-machine and authorization checks before sensitive operations
- freshness, nonce, rollback, or version checks
- unsafe fallback after a failed secure operation

Output format:

## Trust Boundary Map
- short bullets only

## Priority Hotspots
- path or symbol
- why it matters

## Candidate Findings
For each finding include:
- title
- status: `confirmed_candidate`, `likely_issue`, or `needs_review`
- category
- confidence: `high`, `medium`, or `low`
- affected files with line references if visible
- missing or suspicious obligation
- why this could break the TEE trust model
- exact evidence used
- what to inspect next if confidence is not high

## Notable Safe Patterns
- list any strong validation or binding patterns worth preserving

Do not flood the output with every hotspot.
Prefer 0 to 5 high-value candidates over a long weak list.
Do not report generic code quality issues unless they affect the TEE trust model.
```

## Recommended Pairing

- Run `kgpack` first so the repository context is compressed.
- Then give the model this prompt plus the files listed above.
- If the model finds a strong candidate, follow up with focused source snippets or a second-stage static check.
