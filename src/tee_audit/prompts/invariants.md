# Stage 2: TEE Usage Problem Invariant Extraction Prompt

You are a TEE usage problem analyst identifying security invariants in a TEE-enabled Web3 system. Focus specifically on TEE usage problems — instances where TEE primitives are used incorrectly or where TEE is designed inappropriately.

## TEE Usage Problem Boundary

A **TEE usage problem** involves at least one of:
- **TEE primitives**: attestation, sealing, measurement, ECALL/OCALL, quote generation/verification, key management within TEE, freshness guarantees
- **TEE trust boundaries**: the trust boundary that TEE is designed to protect (enclave/host, trusted/untrusted zone separation)
- **TEE trust chain**: the full chain of trust from root of trust through attestation, measurement, and verification — including gaps where chain links are missing or weakened
- **TEE binding & state**: identity binding between TEE artifacts, sealed state continuity, epoch/replay resistance

This covers ALL six taxonomy categories: Trust Boundary Flow, Verification Gap, Binding Weakness, State Continuity, Configuration Integrity, and Design Appropriateness. "Trust-boundary-relevant" means any problem in these categories, not just literal cross-boundary data flows.

Generic code bugs (path traversal, injection, DoS, missing input validation) are NOT TEE usage problems unless they directly undermine a TEE trust boundary.

## Repository Fingerprint

{{fingerprint}}

## Architecture Dossier

{{dossier}}

## Instructions

Derive a SMALL set (5-15) of TEE usage problem invariants. Each invariant must have:

- **id**: Unique identifier in `INV-NN` format (e.g., INV-01, INV-02)
- **description**: One clear sentence describing the TEE security property
- **trust_path**: The TEE trust boundary or data flow this invariant guards
- **tee_interaction**: The specific TEE primitive, trust chain link, or trust boundary interaction this invariant addresses (e.g., "attestation quote verification", "sealed state epoch binding", "ECALL input validation at enclave entry")
- **family**: One of `Flow`, `Guard`, `Binding`, `State`, `Config`, `Design`, `Leakage`
  - **Flow**: Secret or trusted data crosses a TEE trust boundary incorrectly or without proper binding
  - **Guard**: Required TEE verification (attestation, measurement, identity) is missing or incomplete
  - **Binding**: Cryptographic or identity binding between TEE artifacts is partial or absent
  - **State**: Sealed state, checkpoints, or epochs lack proper continuity or replay resistance
  - **Config**: Build flags, debug modes, or deployment configs weaken TEE guarantees
  - **Design**: TEE is used in wrong places, trust paths are incomplete, or protection is over/under-scoped
  - **Leakage**: Output length, error detail, or metadata reveals enclave state or secret-dependent information
- **tee_dimension**: Either `"incorrect_usage"` (TEE is used but wrongly) or `"inappropriate_design"` (TEE is placed incorrectly in the architecture)
- **sources**: Where the trusted/untrusted data originates (list)
- **sinks**: Where the data reaches if the invariant is violated (list)
- **guards**: What checks prevent the violation (list)
- **failure_modes**: What happens if the invariant is violated (list)
- **codeql_expressible**: Whether CodeQL can structurally check this (boolean)

## Family Selection Rules

Use the detailed taxonomy reference below to select the correct family for each invariant. Pay close attention to the **Distinguishing from other families** sections to avoid misclassification.

{{taxonomy_reference}}

## Rules

- Focus on TEE USAGE PROBLEMS only. Do NOT derive invariants about generic code bugs (path traversal, injection, DoS, memory safety) unless they directly undermine a TEE trust boundary.
- Keep the set SMALL and security-relevant. Quality over quantity.
- Every invariant must involve a TEE primitive, trust chain link, or trust boundary interaction. If you cannot articulate the TEE-specific `tee_interaction`, the invariant does not belong here.
- Cover ALL applicable taxonomy categories — do not fixate on one family if the codebase has problems in multiple categories.
- Every finding later must map back to one named invariant.
- If unsure about CodeQL expressibility, set `codeql_expressible` to `false`.

## Taint Specification Extraction (IRIS-style)

For each invariant where `codeql_expressible` is true, also provide **taint_specs** — source/sink/sanitizer triples that describe how tainted data flows through the TEE boundary:

- **source**: The function, method, or API entry point where untrusted or tainted data enters (e.g., "OCALL return value", "host-provided buffer to ECALL", "quote from network", "unsealed blob from host filesystem")
- **sink**: The function, method, or API where tainted data must not reach without proper validation (e.g., "key derivation input", "measurement report field", "seal key material", "enclave private key usage")
- **sanitizer**: The validation function that cleanses the taint, if one exists (e.g., "quote_verify()", "measurement_check()", "policy_validate()"). Set to null if no sanitizer exists.
- **taint_type**: Either "data_flow" (tainted data flows) or "control_flow" (tainted data affects control flow decisions)
- **description**: One sentence explaining why this taint flow matters for TEE security

**Key insight**: You have seen many TEE library APIs in training data. Use that knowledge to identify which APIs are sources of untrusted data (host-side inputs, network data, filesystem reads) and which are security-sensitive sinks (TEE measurement, key material, attestation reports). This is exactly what static analysis needs but cannot derive from code alone.

**Examples of good taint specs**:
- source: "sgx_read_unsealed()" → sink: "enclave_key_derive()" → sanitizer: "verify_seal_version()" (State continuity)
- source: "ECALL parameter from host" → sink: "quote3_report_data_set()" → sanitizer: null (Flow — host controls report_data)
- source: "dcap_quote_verify() input" → sink: "policy_decision()" → sanitizer: "check_tcb_status()" (Guard — unverified quote drives policy)
- source: "enclave processing of secret data" → sink: "HTTP response with variable-length body" → sanitizer: "constant_time_response_padding()" (Leakage — output length reveals secret)
- source: "enclave internal error path" → sink: "RPC error response to host" → sanitizer: "generic_error_wrapper()" (Leakage — error detail exposes enclave state)

Respond with a JSON object containing an `invariants` array matching the schema.
