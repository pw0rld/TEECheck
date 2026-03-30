# Attestation Rule Template

## 1. Goal

Detect code that accepts quote collateral or identity material and makes a trust decision without completing the required verification and binding sequence.

This rule family is meant for SGX/DCAP, TDX, and similar attestation verifiers. It targets usage failures, not memory corruption.

## 2. Threat Model

The attacker can influence or replace collateral fields such as:

- `qe_identity`
- `qe_identity_signature`
- `qe_identity_issuer_chain`
- `tcb_info`
- `tcb_info_signature`
- certificate chains or TCB component arrays

The vulnerability class appears when the verifier:

- parses and trusts identity material before authenticating it
- authenticates the material but does not bind it to the quote or report
- enforces only part of the required policy
- implements different security checks across backends or bindings

## 3. Rule Shape

```json
{
  "rule_id": "ATTESTATION.QE_IDENTITY.MISSING_BINDING_OR_VERIFICATION",
  "title": "Missing attestation identity verification or policy binding",
  "scope": "dcap-sgx, dcap-tdx, quote-verifier",
  "trigger_kinds": [
    "attestation_verification_entry",
    "collateral_parse",
    "identity_material_use"
  ],
  "required_checks": [
    {
      "kind": "issuer_chain_validation",
      "must_dominate": true
    },
    {
      "kind": "identity_signature_validation",
      "must_dominate": true
    },
    {
      "kind": "identity_policy_binding",
      "must_dominate": true
    }
  ],
  "recommended_checks": [
    "debug_attribute_validation",
    "leaf_end_entity_validation",
    "component_wise_tcb_comparison",
    "backend_parity_validation"
  ],
  "severity": "critical",
  "llm_review_required": true
}
```

## 4. Trigger Definition

Emit a candidate when code:

- verifies a quote or report
- parses `qe_identity` or equivalent identity JSON
- reads security-relevant identity fields such as `mrsigner`, `isvprodid`, `isvsvn`, `miscselect`, `attributes`, or TCB component arrays
- returns a `VerifiedReport` or equivalent trust-bearing result

Typical trigger APIs or symbols:

- `verify(...)`
- `verify_with_root_ca(...)`
- `verify_qe_identity_signature(...)`
- `verify_qe_identity_policy(...)`
- `verify_certificate_chain(...)`
- `qe_identity`, `tcb_info`, `qe_report`, `mr_signer`, `isv_prod_id`, `isv_svn`

## 5. Required Obligations

### 5.1 `issuer_chain_validation`

The verifier must prove that the identity signing certificate chains to an accepted trust anchor.

Evidence examples:

- `verify_certificate_chain(...)`
- `extract_certs(...)` followed by trust-anchor validation

### 5.2 `identity_signature_validation`

The verifier must check that the untrusted identity payload is signed by the validated leaf certificate.

Evidence examples:

- `verify_signature(..., qe_identity.as_bytes(), qe_identity_signature)`
- JS or WebCrypto equivalents

### 5.3 `identity_policy_binding`

The verifier must bind the quote or QE report to the authenticated identity.

At minimum, look for checks over:

- `mrsigner`
- `isvprodid`
- `isvsvn`
- `miscselect` and its mask
- `attributes` and their mask

A valid implementation may spread these checks across helpers. The scanner should therefore treat this as an obligation set, not as a single required call.

## 6. Recommended Hardening Checks

These should raise confidence or severity when absent:

- `debug_attribute_validation`
  Reject debug-mode QE or enclave reports where the trust model requires production mode.
- `leaf_end_entity_validation`
  Reject CA certificates used as end-entity signing certs.
- `component_wise_tcb_comparison`
  Compare TCB components element-by-element, not lexicographically.
- `backend_parity_validation`
  Check whether Rust, JS, Go, Python, or FFI bindings enforce the same obligations.

## 7. Evidence Package Requirements

For each candidate, extract:

- verification entry function
- identity parsing site
- trust-anchor or certificate-chain validation site
- signature validation site
- policy-binding checks found and missing
- final trust decision site
- backend name or binding layer
- relevant code snippets and line numbers

Compact finding questions:

- Is untrusted identity material parsed before it is authenticated?
- Does the trust decision depend on identity fields without proof of signature validation?
- Are `mrsigner`, `isvprodid`, `isvsvn`, `miscselect`, and `attributes` all enforced?
- Is the implementation weaker in one backend than in another?

## 8. Confidence Strategy

Classify findings like this:

- `high`
  Trust-bearing result is reachable and one of the required obligations is missing on the same path.
- `medium`
  Required calls exist, but the verifier uses identity fields in a way that suggests incomplete binding.
- `needs_review`
  Obligations are distributed across helpers or across language boundaries and the static proof is incomplete.

## 9. Why `dcap-qvl` Needs This Template

The `dcap-qvl` case shows why a naive call-presence rule is not enough.

In the vulnerable `v0.3.8` release:

- `verify_qe_identity_signature(...)` is present
- `verify_qe_identity_policy(...)` is present
- the main verification path calls both helpers

So a simple rule like "is there any QE identity check" would miss the bug family entirely.

This template instead asks whether the verifier enforces the full trust-binding sequence and whether all backends apply equivalent policy.

## 10. Implementation Notes

For the current scanner, this rule family implies:

- new trigger kinds beyond `memref_use`
- Rust and JavaScript support in the candidate finder
- obligation-set checking instead of single-check presence
- cross-file and cross-backend summaries

The right first implementation is likely:

1. Find quote-verification entrypoints.
2. Track `qe_identity` and `tcb_info` parsing.
3. Record chain validation, signature validation, and policy-binding checks.
4. Emit a finding when a trust decision is reachable without the full obligation set.

A machine-readable starter version of this template now lives at:

- `rules/templates/attestation_qe_identity_template.json`
