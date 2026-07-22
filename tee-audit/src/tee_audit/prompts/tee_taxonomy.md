# TEE Usage Problem Taxonomy — Detailed Reference

This document defines the seven analysis families for classifying TEE (Trusted Execution Environment) usage problems in Web3 projects. Each family captures a distinct category of TEE misuse or design weakness.

A **TEE usage problem** involves at least one of:
- **TEE primitives**: attestation, sealing, measurement, ECALL/OCALL, quote generation/verification, key management within TEE, freshness guarantees
- **TEE trust boundaries**: the enclave/host boundary, trusted/untrusted zone separation
- **TEE trust chain**: the chain from root of trust through attestation, measurement, and verification
- **TEE binding & state**: identity binding between TEE artifacts, sealed state continuity, epoch/replay resistance

Generic code bugs (path traversal, injection, DoS, memory safety) are NOT TEE usage problems unless they directly undermine a TEE trust boundary.

---

## Family: Flow (Trust Boundary Flow)

**Definition**: Secret or trusted data crosses a TEE trust boundary incorrectly — either without encryption, without proper binding, or through an unintended channel.

**TEE primitives involved**:
- ECALL/OCALL parameter passing
- Sealed data read/write between enclave and host
- Attestation report fields (report_data, signature)
- Key material derivation and transfer
- Network I/O from enclave (via proxy or OCALL)

**When to select this family**:
- Attestation result not bound to key release decision
- Sealed data exposed to host without encryption
- Secrets crossing enclave boundary without proper protection
- Host-controlled data influencing enclave decisions without validation
- OCALL return values used in security-critical operations without checks

**Source/sink/sanitizer archetypes**:
- source: "OCALL return value", "host-provided buffer to ECALL", "quote from network", "unsealed blob from host filesystem", "environment variable read in enclave"
- sink: "key derivation input", "measurement report field", "seal key material", "enclave private key usage", "policy decision"
- sanitizer: "input validation", "bounds check", "cryptographic verification", "whitelist filter"

**Distinguishing from other families**:
- vs Guard: Flow is about DATA crossing a boundary; Guard is about CHECKS being missing. A Flow issue may have a guard that's bypassed; a Guard issue is about the guard being absent entirely.
- vs Binding: Flow is about the data path itself; Binding is about the cryptographic linkage between artifacts.
- vs Leakage: Flow is about incorrect data reaching a sink; Leakage is about observable output revealing secrets.

**CWE references**: CWE-345 (Insufficient Verification of Data Authenticity), CWE-346 (Origin Validation Error), CWE-349 (Acceptance of Extraneous Untrusted Data), CWE-494 (Download of Code Without Integrity Check)

**Non-examples**:
- A function that only operates within the enclave on enclave-generated data (no boundary crossing)
- Input validation that's the caller's responsibility, not a trust boundary issue
- Data flow entirely within the untrusted/host side

**CodeQL expressibility**: HIGH — taint tracking from source to sink with sanitizer predicates

---

## Family: Guard (Verification Gap)

**Definition**: Required TEE verification — attestation, measurement, identity, or freshness — is missing, incomplete, or bypassable.

**TEE primitives involved**:
- Quote verification (DCAP/ECDSA/EPID)
- TCB status checking
- Measurement comparison (MRENCLAVE/MRSIGNER)
- Collateral freshness (CRL, TCB info timestamps)
- Identity verification before key release or policy decision

**When to select this family**:
- Attestation performed without full quote verification
- Policy change or secret release without caller attestation check
- Quote accepted without checking TCB status or collateral freshness
- Measurement comparison skipped or incomplete (e.g., only MRENCLAVE, not MRSIGNER)
- Key release based on unverified identity claims

**Source/sink/sanitizer archetypes**:
- source: "unverified attestation quote", "unchecked measurement", "unvalidated identity claim", "stale collateral"
- sink: "policy decision", "key release", "registration acceptance", "secret access"
- sanitizer: "quote_verify()", "measurement_check()", "tcb_status_validate()", "collateral_freshness_check()"

**Distinguishing from other families**:
- vs Flow: Guard is about a CHECK being absent; Flow is about DATA crossing a boundary. If the issue is "this check doesn't exist", it's Guard. If it's "this data reaches here", it's Flow.
- vs Config: Guard is about missing runtime verification; Config is about build/deployment flags weakening guarantees.
- vs Binding: Guard is about verification being incomplete; Binding is about the cryptographic linkage being partial.

**CWE references**: CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature), CWE-351 (Insufficient Type Distinction), CWE-353 (Missing Support for Integrity Check)

**Non-examples**:
- The guard exists in a wrapper or lower-level verifier that is definitely invoked
- A verification that's the responsibility of a different component in the architecture
- Missing checks on non-TEE-specific operations (generic input validation)

**CodeQL expressibility**: HIGH — structural absence queries checking for guard function calls before sensitive operations

---

## Family: Binding (Binding Weakness)

**Definition**: Cryptographic or identity binding between TEE artifacts is partial or absent — measurements, keys, reports, or identities are not properly linked.

**TEE primitives involved**:
- MRENCLAVE/MRSIGNER identity binding
- report_data field binding (key-to-quote binding)
- Seal policy binding (sealed data tied to enclave identity)
- Cross-service identity binding (on-chain vs off-chain identity)
- Epoch/version binding for sealed state

**When to select this family**:
- Measurement/signer binding incomplete (only one checked)
- Report-data not binding key material or identity claims
- Chain/epoch identity not bound to sealed state
- On-chain registration not bound to actual enclave measurement
- Sealed state not bound to creating enclave identity

**Source/sink/sanitizer archetypes**:
- source: "key material", "report data", "identity claim", "seal policy"
- sink: "on-chain registration", "cross-service acceptance", "sealed state key", "attestation output"
- sanitizer: "MRENCLAVE binding", "MRSIGNER binding", "hash binding", "signature binding"

**Distinguishing from other families**:
- vs Flow: Binding is about the LINKAGE between artifacts; Flow is about the data path. Binding asks "are A and B properly connected?", Flow asks "can bad data reach here?"
- vs State: Binding is about identity linkage; State is about continuity across time. A binding issue is about "wrong identity", a state issue is about "wrong version/epoch".
- vs Guard: Binding is about incomplete cryptographic connection; Guard is about missing verification step.

**CWE references**: CWE-322 (Key Exchange without Entity Authentication), CWE-324 (Use of a Key Past its Expiration Date), CWE-328 (Reversible One-Way Hash), CWE-360 (Trust of System Event Data)

**Non-examples**:
- The binding is implemented through a helper function not obvious from the first call site
- A design choice to use MRENCLAVE-only binding (which IS a valid binding, just narrower)
- Binding checks in the verifier that correctly extract and return bound fields

**CodeQL expressibility**: MEDIUM — structural checks for comparison/binding function presence

---

## Family: State (State Continuity)

**Definition**: Sealed state, checkpoints, or epochs lack proper continuity, replay resistance, or rollback resistance.

**TEE primitives involved**:
- Sealed data (SGX seal/unseal operations)
- State versioning and migration
- Epoch counters and monotonicity
- Checkpoint/restore mechanisms
- Anti-rollback counters
- Clone resistance

**When to select this family**:
- Sealed state not bound to epoch or version
- Replayable trust statements or reusable authorizations
- Checkpoint restoration without continuity check
- Clone without monotonicity enforcement
- State migration without version binding
- Missing anti-rollback protection on sealed state

**Source/sink/sanitizer archetypes**:
- source: "unsealed blob from host", "checkpoint data", "epoch state", "replayed sealed data"
- sink: "state restoration", "key derivation", "enclave initialization", "policy enforcement"
- sanitizer: "epoch/nonce validation", "monotonicity check", "version binding", "anti-rollback counter"

**Distinguishing from other families**:
- vs Binding: State is about temporal continuity; Binding is about identity linkage. "Is this the same enclave?" is Binding; "Is this the latest state?" is State.
- vs Guard: State is about continuity properties; Guard is about verification steps. Missing a version check is State; missing an attestation check is Guard.
- vs Flow: State involves persisted data across invocations; Flow involves data crossing a boundary in a single request.

**CWE references**: CWE-294 (Authentication Bypass by Capture-replay), CWE-336 (Same Seed in Pseudo-Random Number Generator), CWE-374 (Passing Mutable Objects to an Untrusted Method), CWE-451 (User Interface (UI) Misrepresentation of Critical Information)

**Non-examples**:
- A repo has recovery code, but the claimed security property does not require stronger continuity than what is implemented
- State that is only used within a single enclave invocation (no persistence/replay concern)
- Version fields that are checked but through an indirect mechanism

**CodeQL expressibility**: MEDIUM — structural checks for version/epoch comparison; limited for semantic continuity analysis

---

## Family: Config (Configuration Integrity)

**Definition**: Build flags, debug modes, feature flags, or deployment configurations weaken TEE security guarantees.

**TEE primitives involved**:
- Debug/production mode flags (SGX debug mode, Gramine insecure mode)
- Feature flags controlling attestation verification strictness
- Environment variables controlling TEE trust decisions
- Build configuration (signing keys, measurement divergence)
- Deployment configuration (TLS, network exposure)

**When to select this family**:
- Simulation or debug mode reachable in production
- Feature flags that weaken attestation verification
- Environment variables controlling TEE trust decisions
- Build-time signing key mismanagement
- Deployment configs exposing TEE interfaces incorrectly
- Debug output or logging in production TEE code

**Source/sink/sanitizer archetypes**:
- source: "env vars", "config files", "feature flags", "build-time constants"
- sink: "TEE initialization", "attestation enablement", "security policy"
- sanitizer: "production mode check", "flag validation", "config verification"

**Distinguishing from other families**:
- vs Guard: Config is about build/deployment SETTINGS weakening security; Guard is about runtime VERIFICATION being missing. A debug flag that skips attestation is Config; a missing attestation call is Guard.
- vs Design: Config is about incorrect settings within a correct architecture; Design is about the architecture itself being wrong.
- vs Flow: Config is about configuration enabling weaknesses; Flow is about data flowing incorrectly.

**CWE references**: CWE-489 (Active Debug Code), CWE-733 (Compiler Optimization Removal or Modification of Security-critical Code), CWE-776 (XML Entity Expansion), CWE-276 (Incorrect Default Permissions)

**Non-examples**:
- A debug path exists but is strictly test-only or impossible in production
- Configuration that only affects non-TEE-related functionality
- Build-time constants that are correct and appropriate

**CodeQL expressibility**: HIGH — structural search for debug flags, env var reads, conditional compilation

---

## Family: Design (Design Appropriateness)

**Definition**: TEE is used in wrong places, trust paths are incomplete, or protection is over/under-scoped relative to the actual threat model.

**TEE primitives involved**:
- TEE placement in architecture (which components are protected)
- Trust path completeness (are all critical paths covered)
- Trust boundary definition (is the boundary correctly placed)
- Threat model alignment (does TEE address the actual threats)

**When to select this family**:
- TEE protecting wrong components (e.g., protecting public data while leaving secrets exposed)
- Trust paths that bypass the enclave entirely
- Over-reliance on TEE for non-sensitive data (wasteful, not a vulnerability per se)
- Missing TEE where trust boundary requires it within existing TEE usage patterns
- TEE used as a substitute for proper access control
- Inconsistent trust assumptions across system components

**Source/sink/sanitizer archetypes**:
- This family is primarily about architectural analysis, not code-level taint tracking.
- source: "architectural trust assumption", "trust path design"
- sink: "security guarantee claim", "user-facing promise"
- sanitizer: "consistent trust model", "complete trust path coverage"

**Distinguishing from other families**:
- vs Config: Design is about the ARCHITECTURE being wrong; Config is about SETTINGS being wrong. "TEE shouldn't protect this component" is Design; "TEE debug mode is enabled" is Config.
- vs Guard: Design is about the trust model being incomplete; Guard is about a specific verification step missing. "No attestation in the architecture" is Design; "Attestation exists but skips a check" is Guard.
- vs Flow: Design is about the trust boundary placement; Flow is about data crossing an existing boundary.

**CWE references**: CWE-1021 (Improper Restriction of Rendered UI Layers), CWE-1188 (Insecure Default Initialization of Resource), CWE-1234 (Hardware Internal or Alternate Modes are Accessible)

**Non-examples**:
- An architecture choice that is debatable but defensible (not clearly wrong)
- Missing features that haven't been claimed as security guarantees
- Performance trade-offs that don't affect security properties

**CodeQL expressibility**: LOW — primarily requires architectural reasoning; CodeQL can detect some patterns (e.g., unprotected paths) but cannot assess design appropriateness holistically.

---

## Family: Leakage (Output & Metadata Leakage)

**Definition**: Output length, error detail, or metadata reveals enclave state or secret-dependent information to untrusted observers.

**TEE primitives involved**:
- Response body serialization (variable-length output from enclave processing)
- Error message propagation (enclave internal errors exposed to host/network)
- Logging and debug output (secret-dependent state in logs)
- HTTP/RPC response headers (TEE configuration metadata)
- Timing side-effects observable through output differences

**When to select this family**:
- Response body length varies based on secret data processed in enclave
- Error messages expose enclave internals (configuration, measurements, key material)
- Metadata headers reveal TEE configuration or identity
- Debug output includes secret-dependent state
- Error detail varies by enclave code path, revealing processing state

**Source/sink/sanitizer archetypes**:
- source: "enclave processing of secret data", "internal error states", "secret-dependent computation"
- sink: "HTTP response body", "RPC error message", "log output", "response headers"
- sanitizer: "constant-time response padding", "generic error wrapper", "length normalization", "error message sanitization"

**Distinguishing from other families**:
- vs Flow: Leakage is about OBSERVABLE OUTPUT revealing secrets; Flow is about data reaching an INCORRECT SINK. If the output channel is the intended one but leaks info, it's Leakage. If data reaches an unintended channel, it's Flow.
- vs Config: Leakage is about runtime output revealing secrets; Config is about build/deployment settings weakening security. Debug logging of secrets could be either — classify based on whether the issue is the LOGGING (Config) or the OUTPUT CONTENT (Leakage).

**CWE references**: CWE-201 (Information Exposure Through Sent Data), CWE-215 (Information Exposure Through Debug Information), CWE-497 (Exposure of System Data to an Unauthorized Control Sphere), CWE-532 (Insertion of Sensitive Information into Log File)

**Non-examples**:
- Output padding or constant-time operations already normalize the response
- The varying output is only visible within the enclave itself (no external observation)
- Timing differences that require physical access to measure (outside scope of static analysis)
- Memory access pattern side-channels (outside scope of static analysis)

**Important scope note**: This family focuses on **output length and metadata leakage** observable through static analysis of code patterns. It does NOT cover timing side-channels, cache-based attacks, or memory access pattern analysis, which require different detection approaches.

**CodeQL expressibility**: HIGH — taint tracking from secret sources to response/output sinks; structural checks for error propagation patterns

---

## TEE Dimension Classification

Each finding has a `tee_dimension` that classifies whether the TEE usage is incorrect or the design is inappropriate:

- **incorrect_usage**: TEE primitives exist and are used, but incorrectly. The TEE is in the right place, but the implementation has bugs (e.g., attestation verification skips a step, sealed data is not bound to epoch).

- **inappropriate_design**: TEE is placed incorrectly in the architecture, or the trust model is fundamentally flawed (e.g., TEE protects the wrong component, trust paths bypass the enclave, TEE is used as a substitute for proper access control).

Rule of thumb: If the fix is "add/change a check or binding", it's incorrect_usage. If the fix is "redesign the trust model", it's inappropriate_design. The Design family is almost always inappropriate_design; other families can be either.
