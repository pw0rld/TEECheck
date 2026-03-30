# Prompts

The current demo does not call a live model.

Instead, the scanner writes markdown review bundles for findings whose status is `needs_review`. Those bundles are the prompt material we can later send to an LLM backend.

The GitNexus MVP adds a second prompt source:

- `reports/knowledge-pack.md`

That file is meant to be paired with a TEE usage audit skill so the model can reason over repository structure before diving into raw code.

The repository now includes:

- `prompts/gitnexus_tee_audit_prompt.md`
- `skills/tee-usage-audit/SKILL.md`

The intended flow is:

1. run `kgpack`
2. give the model the knowledge pack
3. pair it with the TEE usage audit skill
4. inspect only the top hotspots in real source before making claims
