# TEE Usage Scanner

Prototype project for a TEE usage vulnerability scanner.

The current goal is to validate a scanning workflow that combines:

- Go as the scanner orchestration layer
- Joern as the program graph backend
- A rule-driven detector for TEE usage obligations
- Compact evidence packages extracted from program analysis
- An LLM as a second-stage reviewer for ambiguous findings

This repository starts with planning and project scaffolding so we can iterate toward an MVP without mixing it into the existing codebases in this workspace.

The repository now contains two exploratory tracks:

- `Joern + rules`, which treats program analysis as structured evidence
- `GitNexus + AI`, which treats the repository graph as compressed audit context

The GitNexus track now includes:

- a remote Orb-backed graph export path
- a Go knowledge-pack generator
- a Codex/LLM audit prompt template
- a repository-local TEE audit skill draft

## Current Status

Active prototype stage.

The most important design document is:

- `docs/SCANNER_OUTLINE.md`
- `docs/GITNEXUS_MVP.md`

## Initial Scope

- Language: C/C++
- TEE focus: OP-TEE / GlobalPlatform style APIs
- Scan target: trusted application (TA) code first
- Detection style: missing validation, missing binding, missing state checks, insecure fallback

## Planned Architecture

1. Use Joern to build a code property graph from TA code.
2. Run TEE-specific graph queries to emit evidence packages.
3. Evaluate those packages with deterministic rules in Go.
4. Generate LLM review bundles for uncertain cases.
5. Emit structured findings and reports.

## Repository Layout

```text
tee-usage-scanner/
├── cmd/
├── docs/
├── fixtures/
├── internal/
├── prompts/
├── rules/
├── samples/
├── skills/
└── scripts/
```

## Local Demo Usage

### GitNexus Knowledge Pack

The simplest GitNexus-inspired MVP can either ingest an existing graph export or trigger a remote export on Orb first.

For a local fixture:

```bash
go run ./cmd/tee-usage-scanner kgpack \
  --graph-json fixtures/gitnexus/sample_graph.json \
  --focus tee \
  --report reports/knowledge-pack.json \
  --prompt reports/knowledge-pack.md
```

This command assumes you already have a GitNexus graph export JSON file. It does not yet talk to a live GitNexus service. Instead, it compresses the graph into an AI-friendly knowledge pack for manual or LLM-assisted review.

For the Orb-backed one-command path:

```bash
go run ./cmd/tee-usage-scanner kgpack \
  --src /Users/pw0rld/Desktop/TEENET/TEECheck/dcap-qvl-v038 \
  --gitnexus-ssh-target orb-vscode \
  --graph-json reports/dcap-qvl-gitnexus-graph.json \
  --focus tee \
  --report reports/dcap-qvl-knowledge-pack.json \
  --prompt reports/dcap-qvl-knowledge-pack.md
```

This command first runs `scripts/gitnexus/export_graph.mjs` on the remote Orb host through SSH, writes the graph export into the shared workspace, and then turns that export into a knowledge pack locally.

To hand the result to Codex or another LLM, pair:

- `reports/knowledge-pack.md`
- `reports/knowledge-pack.json`
- `prompts/gitnexus_tee_audit_prompt.md`
- `skills/tee-usage-audit/SKILL.md`

The fixture-backed path is still useful for quick rule iteration:

```bash
go run ./cmd/tee-usage-scanner scan \
  --fixture-dir fixtures/optee_param_types \
  --report reports/findings.json \
  --review-dir reports/reviews
```

This reads prebuilt evidence packages, evaluates the first TEE rule, and emits a report plus optional LLM review bundles.

The attestation rule template can also be exercised through fixtures without touching the live Joern extractor yet:

```bash
go run ./cmd/tee-usage-scanner scan \
  --fixture-dir fixtures/attestation_qe_identity \
  --rule-dir rules/templates \
  --report reports/attestation-template.json \
  --review-dir reports/reviews-attestation-template
```

This path is useful for iterating on SGX/DCAP-style obligation rules before we refine the live Joern extractor.

The live Joern-backed path now works against the OrbStack container we started from:

```bash
go run ./cmd/tee-usage-scanner scan \
  --src /Users/pw0rld/Desktop/TEENET/TEECheck/tee-usage-scanner/samples/optee_ta/positive \
  --joern-ssh-target orb-vscode \
  --report reports/joern-positive.json \
  --review-dir reports/reviews-joern-positive
```

For the negative sample:

```bash
go run ./cmd/tee-usage-scanner scan \
  --src /Users/pw0rld/Desktop/TEENET/TEECheck/tee-usage-scanner/samples/optee_ta/negative \
  --joern-ssh-target orb-vscode \
  --report reports/joern-negative.json \
  --review-dir reports/reviews-joern-negative
```

These commands use:

- the Joern server endpoint at `http://127.0.0.1:8080/query-sync`
- the OrbStack SSH target `orb-vscode`
- the container workspace mount `/workspace/tee-usage-scanner`

There is now also a live attestation extraction path for quote-verifier style projects. For example:

```bash
go run ./cmd/tee-usage-scanner scan \
  --src /Users/pw0rld/Desktop/TEENET/TEECheck/dcap-qvl-v038 \
  --joern-ssh-target orb-vscode \
  --joern-workspace /workspace/TEECheck \
  --rule-dir rules/templates \
  --report reports/dcap-qvl-live-attestation.json \
  --review-dir reports/reviews-dcap-qvl-live-attestation
```

On the current `dcap-qvl-v038` sample, this emits one live attestation evidence package and zero findings, which matches the current rule template because the JavaScript verifier path does contain all required policy-binding fields.

## Joern Status

The repository now has a working Joern server integration for two evidence families. It currently supports:

- importing a source tree through the Joern server
- extracting `memref.buffer` candidates
- extracting same-method `param_types` and `memref.size` checks
- extracting quote-verifier attestation candidates with issuer-chain, signature, policy-binding, and trust-decision sites
- emitting real evidence packages into the Go rule engine

The current limitations are:

- the extractor is intentionally narrow and only covers the first rule
- the attestation extractor currently matches the JavaScript binding path in `dcap-qvl`; Rust-first extraction still needs dedicated support
- helper functions are marked `needs_review` instead of being treated as definite findings
- multi-file projects still rely on basename-based file resolution
- the script stubs under `scripts/joern/` are not yet the source of truth; the live query is built in `internal/joern/client.go`

## Current Demo Rule

The first end-to-end rule is:

- `TEE.PARAM_TYPES.MISSING_BEFORE_MEMREF_USE`

It flags TA code that uses `params[i].memref` without a dominating `param_types` validation.

The repository also now contains an attestation rule template for SGX/DCAP-style quote verification:

- `rules/templates/attestation_qe_identity_template.json`

That template introduces field-level obligations such as masked `miscselect` and `attributes` enforcement.

The live extractor can already populate this template shape for quote-verifier style JavaScript code, including:

- `verification_entry`
- `identity_parsing_site`
- `certificate_chain_validation_site`
- `identity_signature_validation_site`
- `policy_binding_site`
- `trust_decision_site`

## Next Implementation Targets

1. Move the live Joern query out of Go and into versioned scripts under `scripts/joern/`.
2. Replace same-method heuristics with stronger control-flow reasoning.
3. Add a second rule for bounds validation.
4. Add a real LLM backend behind the review bundle generator.
5. Improve the TEE-specific hotspot ranking and trust-boundary hints in the knowledge pack.
