# TEE Audit Obligations

Use this checklist when turning GitNexus hotspots into concrete audit questions.

## 1. Boundary Revalidation

Ask whether untrusted inputs are revalidated inside the trusted boundary.

Look for:

- command identifiers, selectors, or opcodes trusted too early
- buffers, offsets, lengths, and counts used without trusted-side validation
- shared memory, host-provided collateral, or config objects accepted without re-checking structure or bounds

## 2. Attestation And Identity Verification

Ask whether trust decisions are backed by complete verification.

Look for:

- missing issuer-chain validation
- missing signature verification on identity or collateral objects
- missing binding between verified identity data and the object being trusted
- partial policy checks that parse fields but do not enforce them

## 3. Binding And Authorization

Ask whether the code binds sensitive actions to the correct principal.

Look for:

- session or caller checks that are absent or happen too late
- object, handle, or key usage not tied to the current session or identity
- sensitive commands reachable without an authorization gate

## 4. State Machine Safety

Ask whether privileged operations require the right prior state.

Look for:

- initialize, open, authenticate, or verify steps that can be skipped
- operations succeeding before a required provisioning or attestation phase
- stale or reused state that should have been invalidated

## 5. Freshness And Replay Resistance

Ask whether the code enforces newness.

Look for:

- nonce, challenge, timestamp, version, or monotonic-counter checks that are missing
- rollback or downgrade opportunities
- cached trust decisions reused without checking freshness assumptions

## 6. Secure Failure

Ask what happens when the secure path fails.

Look for:

- fallback to a weaker path after verification failure
- best-effort verification where failure only logs a warning
- error handling that preserves access to sensitive operations or secrets

## 7. Secret And Result Handling

Ask whether trusted results or secrets outlive their safety conditions.

Look for:

- secrets copied into untrusted buffers too early
- trust results exposed before all obligations are satisfied
- sensitive data or internal state leaked through logs, error messages, or host-visible structures
