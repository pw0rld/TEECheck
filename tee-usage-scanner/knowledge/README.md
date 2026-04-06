# Knowledge Layer

This directory is the persistent knowledge surface for the collaborative
TEECheck harness.

It is intentionally not a plain document-chunk RAG bucket.

The preferred flow is:

`raw sources -> curator process -> wiki pages -> agent lookup`

## Layout

```text
knowledge/
├── raw/
├── wiki/
└── learned/
```

### `raw/`

For original sources such as:

- CVEs
- papers
- SDK docs
- prior reviews

### `wiki/`

For normalized, reusable pages that agents should prefer during analysis.

Suggested subareas:

- `obligations/`
- `patterns/`
- `apis/`
- `projects/`
- `open-questions/`

### `learned/`

For persistent output from human review and future curator updates:

- true positives
- false positives
- review memory

## Current Seed Pages

- `wiki/obligations/trust-boundary-revalidation.md`
- `wiki/obligations/attestation-identity-verification.md`
- `wiki/patterns/authorization-caller-binding.md`
