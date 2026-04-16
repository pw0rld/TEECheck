# Stage 2: Invariant Extraction Prompt

You are a security analyst identifying trust-path invariants in a TEE-enabled Web3 system. Based on the fingerprint and dossier below, derive security invariants.

## Repository Fingerprint

{{fingerprint}}

## Architecture Dossier

{{dossier}}

## Instructions

Derive a SMALL set (5-15) of security-relevant invariants. Each invariant must have:

- **id**: Unique identifier in `INV-NN` format (e.g., INV-01, INV-02)
- **description**: One clear sentence describing the security property
- **trust_path**: The trust boundary or data flow this invariant guards
- **family**: One of `Flow`, `Guard`, `Binding`, `State`, `Config`
  - **Flow**: A value crosses a trust boundary and reaches a dangerous sink
  - **Guard**: A required check exists before a critical action
  - **Binding**: Cryptographic or identity binding between artifacts
  - **State**: Continuity, replay resistance, rollback resistance
  - **Config**: Flags, features, deployment assumptions
- **sources**: Where the trusted/untrusted data originates (list)
- **sinks**: Where the data reaches if the invariant is violated (list)
- **guards**: What checks prevent the violation (list)
- **failure_modes**: What happens if the invariant is violated (list)
- **codeql_expressible**: Whether CodeQL can structurally check this (boolean)

## Analysis Family Selection Rules

- **Flow**: Secret/plaintext to log, host config to trusted decision, untrusted artifact to key release
- **Guard**: Attestation without full verification, policy change without caller checks, recovery bypassing admission
- **Binding**: Measurement/signer binding, report-data binding, chain/epoch binding
- **State**: Stale state reuse, recovery without continuity, replayable trust statements, clone assumptions
- **Config**: Simulation/debug paths, feature flags weakening validation, environment-driven trust

## Rules

- Keep the set SMALL and security-relevant. Quality over quantity.
- Every finding later must map back to one named invariant.
- If unsure about CodeQL expressibility, set `codeql_expressible` to `false`.

Respond with a JSON object containing an `invariants` array matching the schema.
