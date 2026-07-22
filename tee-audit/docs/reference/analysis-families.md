# Analysis Families for TEE×Web3 Audits

This document defines the seven analysis families used to classify and analyze security invariants. The goal is to choose the right tool for each property, not to force everything into taint analysis.

## 1. Flow Analysis

**Use when** a value crosses a trust boundary and reaches a dangerous sink.

Best-fit properties:
- Secret or plaintext to log or telemetry
- Host config or environment input to trusted decision
- Untrusted artifact to key release, admission, or policy change

Best tools:
- CodeQL for supported languages
- Structural search (grep, Semgrep) for smaller codebases or unsupported languages

Required proof:
- A concrete source
- A concrete sink
- No sufficient guard on the live path

Common false positives:
- The flow exists but the sink is test-only
- The value is transformed into a safe representation before the sink

## 2. Guard Analysis

**Use when** the core question is whether a required check exists before a critical action.

Best-fit properties:
- Attestation object accepted without full verification
- Policy change or secret release without caller checks
- Recovery or migration path bypassing normal admission checks

Best tools:
- CodeQL for call-path and structural guard checks
- Structural search for required helper invocation and feature-gate presence
- Agent-assisted review to validate live-path reachability

Required proof:
- The sink or dangerous action
- The expected guard
- Evidence the guard is absent, bypassed, or incomplete on the live path

Common false positives:
- The guard exists in a wrapper or lower-level verifier that is definitely invoked

## 3. Binding Analysis

**Use when** the project relies on cryptographic or identity binding between artifacts.

Best-fit properties:
- Measurement or signer binding
- Report-data or public-key binding
- Chain, epoch, network, or version binding
- On-chain assumption versus off-chain identity mismatch

Best tools:
- CodeQL or structural checks for comparison presence
- Agent-assisted review for semantic binding correctness

Required proof:
- The artifact being trusted
- The expected bound value or policy source
- The missing or incomplete comparison

Common false positives:
- The binding is implemented through a helper that is not obvious from the first call site

## 4. State/Lifecycle Analysis

**Use when** the property depends on continuity, replay resistance, rollback resistance, anti-cloning, or upgrade semantics.

Best-fit properties:
- Stale state reuse
- Recovery without sufficient continuity binding
- Clone or anti-fork assumptions
- Replayable trust statements or reusable authorizations

Best tools:
- Agent-assisted review
- Focused structural searches
- Checklist-driven reasoning from state stores, counters, epochs, versions, and sealing logic

Required proof:
- The relevant state machine or lifecycle step
- The continuity or replay property the design relies on
- The missing state binding, monotonicity, or replay defense

Common false positives:
- A repo has recovery code, but the claimed security property does not require stronger continuity than what is implemented

## 5. Config/Build/Deployment Analysis

**Use when** the security posture depends on flags, features, deployment assumptions, or documented boundaries.

Best-fit properties:
- Simulation or debug paths
- Feature flags that weaken validation
- Environment-driven trust assumptions
- Doc or code mismatches around exposure or internal-only endpoints

Best tools:
- Structural search
- Semgrep-style checks
- Doc review
- Agent verification of deployment assumptions

Required proof:
- The weakening flag, config, or assumption
- Evidence it affects the relevant production or operator path

Common false positives:
- A debug path exists but is strictly test-only or impossible in the documented production model

## 6. Leakage Analysis

**Use when** output metadata or error responses reveal enclave state or secret-dependent information.

Best-fit properties:
- Response body length varies based on secret data processed in the enclave
- Error messages expose enclave internals (configuration, measurements, key material)
- Metadata headers reveal TEE configuration or identity
- Debug output includes secret-dependent state

Best tools:
- CodeQL taint tracking from secret sources to response/output sinks
- Agent-assisted review for semantic output-length analysis

Required proof:
- A concrete source of secret data inside the enclave
- An output channel where length or detail varies with the secret
- Evidence that the variation is observable by an untrusted party

Common false positives:
- Output padding or constant-time operations already normalize the response
- The varying output is only visible within the enclave itself

Note: This family focuses on **output length and metadata leakage**, not timing or memory side-channels. Timing and memory access patterns are harder to exploit and outside the scope of static analysis.

## 7. Design Appropriateness Analysis

**Use when** TEE is placed incorrectly in the architecture, trust paths are incomplete, or protection is over/under-scoped.

Best-fit properties:
- TEE protecting wrong components while leaving secrets exposed
- Trust paths that bypass the enclave entirely
- Over-reliance on TEE for non-sensitive data
- Missing TEE where trust boundary requires it
- TEE used as substitute for proper access control

Best tools:
- Agent-assisted review for architectural reasoning
- Checklist-driven analysis of trust model completeness

Required proof:
- The architectural trust assumption or claim
- Evidence the trust path is incomplete or misplaced
- Why the current design fails to meet stated security goals

Common false positives:
- An architecture choice that is debatable but defensible
- Missing features not claimed as security guarantees

## Tool Selection Rule

Choose the tool that best matches the property:
- When a trust-relevant language is supported locally, use CodeQL as one mandatory deterministic lane
- Prefer CodeQL when the property can be made structural
- Prefer simple structural searches for flags, helpers, config, and obvious guard presence
- Prefer agent-assisted review for protocol-state, lifecycle, and trust-model mismatches

Do not treat baseline CodeQL as sufficient coverage for lifecycle, rollback, anti-cloning, or trust-model questions.

## Output Rule

For every invariant, record:
- Analysis family
- Primary tool
- Proof required
- Likely false-positive conditions
