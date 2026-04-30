# TEECheck Example Finding Review

This document is a human review of the findings under `examples/`.
Its purpose is scanner evaluation, not vulnerability disclosure. A
`confirmed_candidate` emitted by TEECheck is treated as a scanner claim,
not as a true vulnerability until it survives source-level review.

## Verdict Taxonomy

| Verdict | Meaning |
| --- | --- |
| `true_positive` | The scanner identified a real security weakness or strong vulnerability candidate in the reviewed commit. |
| `design_risk` | The code fact is real, but exploitability depends on deployment, feature flags, caller contracts, or protocol intent. |
| `needs_context` | The finding may be valid, but the example artifacts do not contain enough code or call-flow evidence. |
| `false_positive` | Source review contradicts the scanner's conclusion. |
| `no_issue_observed` | The scanner correctly rejected or downgraded the issue. |

## High-Level Results

| Example | Scanner posture | Human review |
| --- | --- | --- |
| `oasis-sdk-scan` | 4 findings; 3 `needs_review`, 1 `no_issue_observed` | No confirmed vulnerability. Mostly boundary-mapping uncertainty in test/proc-macro code. |
| `mobilecoin-l3-v13` through `mobilecoin-l3-v20` | Historical L3 runs | Not suitable as truth data. The reports themselves document prompt/context defects and earlier false precision. |
| `mobilecoin-l3-v22` | 2 `confirmed_candidate`, 6 `needs_review`, 3 `no_issue_observed` | Mostly `needs_context` / `design_risk`. The strongest item depends on whether clients are expected to attest. |
| `oasis-core-scan` | 1 high `confirmed_candidate` | The high finding is a `false_positive`; source shows several checks that the report claimed were absent. |
| `phala-blockchain-scan` | 2 `confirmed_candidate`, several high `needs_review` | Mixed: real DoS and DCAP attribute risk; IAS finding is a false positive due to missed outer validation. |
| `phala-dcap-qvl-scan` | 1 high `confirmed_candidate` | Real dangerous feature, but not default; label as `design_risk`, not default vuln. |
| `quorumos-scan` | 3 high `confirmed_candidate` | Mixed: nonce and timestamp issues are real candidates; `validate_manifest` claim is a clear false positive. |

## Reviewed Findings

### MobileCoin v22

Report: `examples/mobilecoin-l3-v22-scan/REPORT.md`

| Finding | Scanner status | Human verdict | Notes |
| --- | --- | --- | --- |
| `mobilecoin@59a52d3:tee:attestation:001` Missing attestation verification in `ClientAuthRequestInput` | `confirmed_candidate` | `needs_context` / possible `design_risk` | The code fact is real: `NodeAuthRequestInput` parses and verifies DCAP evidence, while `ClientAuthRequestInput` reads `_payload` and proceeds. But the client path uses Noise `HandshakeNX`, which usually means the initiator has no static identity. This is only a vulnerability if the product requires client enclave identity. |
| `mobilecoin@59a52d3:tee:attestation:006` `verify_report` only wraps `sgx_verify_report` | `confirmed_candidate` | `design_risk` | The wrapper really only calls `sgx_verify_report`. That is not itself a vulnerability unless callers treat it as full remote-attestation policy enforcement. The scanner should label this as wrapper-contract documentation / call-site review. |
| `mobilecoin@59a52d3:tee:attestation:005` `Quote::verify` incomplete | `needs_review` | `needs_context` | The report states the relevant implementation was not in the snippet. Correct downgrade. |
| `mobilecoin@59a52d3:tee:authorization:002` `EnclaveRouter::peer_init` | `needs_review` | `needs_context` | The target implementation was not visible in the packet. |
| `mobilecoin@59a52d3:tee:attestation:003` `get_verifier` policy not visible | `needs_review` | `needs_context` | The finding is about delegated policy. Requires call graph and `get_verifier`. |
| `mobilecoin@59a52d3:tee:attestation:007` DCAP nonce lifecycle | `needs_review` | `needs_context` | Correctly requires caller-level nonce lifecycle review. |
| `mobilecoin@59a52d3:tee:attestation:009` report generation | `no_issue_observed` | `no_issue_observed` | Scanner rejected the issue. |
| `mobilecoin@59a52d3:tee:attestation:010` `Report::new` | `no_issue_observed` | `no_issue_observed` | Scanner rejected the issue. |
| `mobilecoin@59a52d3:tee:key_management:011` `sgx_get_key` FFI | `no_issue_observed` | `no_issue_observed` | Scanner rejected the issue. |

Source checks:

- `NodeAuthRequestInput` verifies DCAP evidence; `ClientAuthRequestInput` discards `_payload`: <https://github.com/mobilecoinfoundation/mobilecoin/blob/59a52d3/attest/ake/src/responder.rs#L137-L200>
- `verify_report` is a thin SGX FFI wrapper: <https://github.com/mobilecoinfoundation/mobilecoin/blob/59a52d3/sgx/service/src/lib.rs#L40-L46>

Scanner lesson: do not upgrade "unauthenticated mode exists" into
"attestation bypass" without protocol-role semantics. Noise pattern names
(`NX`, `IX`) are important security context.

### Oasis Core

Report: `examples/oasis-core-scan/REPORT.md`

| Finding | Scanner status | Human verdict | Notes |
| --- | --- | --- | --- |
| `oasis-core@e650c8e:tee:attestation:004` Incomplete quote verification in IAS handler | `confirmed_candidate` | `false_positive` | The report claims the verifier omits quote-body integrity and identity checks. Source shows AVR signature verification, timestamp freshness, quote status validation, GID blacklist, debug flag rejection, minimum TCB evaluation check, and returns `MRENCLAVE`/`MRSIGNER` as `VerifiedQuote.identity` for policy checks. |
| `oasis-core@e650c8e:tee:authorization:006` missing caller binding in policy auth | `needs_review` | `needs_context` | Needs call-site and consensus/runtime policy flow. |
| `oasis-core@e650c8e:tee:boundary:002` `AttestationHandler` revalidation | `needs_review` | `needs_context` | Depends on `Host` trait and RPC boundary guarantees. |
| `oasis-core@e650c8e:tee:attestation:003` quote replay protection | `needs_review` | `needs_context` | Requires full caller review. |
| `oasis-core@e650c8e:tee:boundary:005` dispatcher revalidation | `needs_review` | `needs_context` | Packet was affected by truncated context. |
| `oasis-core@e650c8e:tee:attestation:001` replay protection in `Identity::set_quote` | `no_issue_observed` | `no_issue_observed` | Scanner rejected the issue. |

Source check:

- IAS verify path checks signature, timestamp, status, GID, debug flag, TCB eval number, and returns identity: <https://github.com/oasisprotocol/oasis-core/blob/e650c8e/runtime/src/common/sgx/ias.rs#L247-L344>

Scanner lesson: returning identity to the caller is a valid policy split.
The scanner should distinguish "extracts verified identity for upper-layer
policy" from "accepts any identity".

### Phala Blockchain

Report: `examples/phala-blockchain-scan/REPORT.md`

| Finding | Scanner status | Human verdict | Notes |
| --- | --- | --- | --- |
| `phala-blockchain@654b1b6:tee:attestation:001` governance-controlled attestation bypass | `needs_review` | `design_risk` | The `None if opt_out_enabled` path really returns a `ConfidentialReport` with no provider, empty runtime hash, and confidence level 128. Whether this is exploitable depends on production config and how confidence level 128 is treated. |
| `phala-blockchain@654b1b6:tee:attestation:002` incomplete IAS attestation verification | `confirmed_candidate` | `false_positive` | The report inspected `verify_signature` in isolation. The outer `validate_ias_report` parses quote fields, validates quote status/advisory IDs through `IasFields::from_ias_report`, checks pruntime allowlist when enabled, checks report freshness, and checks user data hash. |
| `phala-blockchain@654b1b6:tee:attestation:003` missing debug/attribute verification in DCAP | `needs_review` | `true_positive` / strong candidate | Source explicitly says "skip verify_misc_select_field" and "skip verify_attributes_field". If debug/attribute policy is required for production trust, this is a real gap. |
| `phala-blockchain@654b1b6:tee:key_management:005` panic on master key unseal/decode/signature failure | `confirmed_candidate` | `true_positive` for DoS/robustness | Source uses `expect` and `assert!` in key unsealing and integrity checks; corruption or write access to sealed storage can trigger enclave process failure. Severity depends on attacker write access. |
| `phala-blockchain@654b1b6:tee:boundary:004` missing boundary revalidation | `needs_review` | `needs_context` | Requires full implementation and entrypoint review. |
| `phala-blockchain@654b1b6:tee:attestation:006` DCAP collateral handling | `needs_review` | `needs_context` | Requires the full `sgx_attestation::dcap` path and collateral trust policy. |

Source checks:

- Opt-out path: <https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L119-L156>
- IAS outer validation: <https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L45-L90> and <https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L161-L190>
- DCAP attribute skip: <https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-attestation/src/dcap.rs#L27-L53>
- Master key panic paths: <https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/phactory/src/system/master_key.rs#L45-L117>

Scanner lesson: inner helper functions are not security boundaries by
themselves. The scanner should inspect the enclosing validation flow before
claiming missing checks.

### Phala dcap-qvl

Report: `examples/phala-dcap-qvl-scan/REPORT.md`

| Finding | Scanner status | Human verdict | Notes |
| --- | --- | --- | --- |
| `dcap-qvl@90c4c9f:tee:attestation:001` TCB status override bypass | `confirmed_candidate` | `design_risk` | The dangerous API is real and applies the override after signature verification and before later checks. But it is behind the non-default `danger-allow-tcb-override` feature. This should not be treated as a default vulnerability without evidence that production builds enable it. |
| `dcap-qvl@90c4c9f:tee:attestation:005` unverified PCK certificate parsing | `needs_review` | `design_risk` | Parser-only APIs can be safe if documented and never used for trust decisions before verification. Needs call-site review. |
| `dcap-qvl@90c4c9f:tee:attestation:004` caller-provided `now` | `needs_review` | `design_risk` | Libraries commonly accept caller time. Risk depends on caller trust boundary. |
| `dcap-qvl@90c4c9f:tee:boundary:002` C FFI validation | `needs_review` | `needs_context` | Original packet lacked implementation lines. |
| `dcap-qvl@90c4c9f:tee:boundary:006` Python FFI validation | `needs_review` | `needs_context` | Requires `PyQuote::parse` review. |
| `dcap-qvl@90c4c9f:tee:attestation:003` collateral parsing/verification separation | `needs_review` | `design_risk` | Valid separation if verifier is mandatory before trust decisions. |
| `dcap-qvl@90c4c9f:tee:attestation:007` quote parse vs verify state | `needs_review` | `design_risk` | Type-state hardening suggestion, not a proven vulnerability. |

Source checks:

- Dangerous override API: <https://github.com/Phala-Network/dcap-qvl/blob/90c4c9f/src/verify.rs#L143-L173>
- Override applied after TCB signature verification: <https://github.com/Phala-Network/dcap-qvl/blob/90c4c9f/src/verify.rs#L806-L816>
- Feature is non-default: <https://github.com/Phala-Network/dcap-qvl/blob/90c4c9f/Cargo.toml#L91-L119>

Scanner lesson: feature flags must be part of the finding. A non-default
`danger-*` API should be reported as configuration/API risk, not as an
unconditional vulnerability.

### QuorumOS / qos

Report: `examples/quorumos-scan/REPORT.md`

| Finding | Scanner status | Human verdict | Notes |
| --- | --- | --- | --- |
| `qos@df1e355:tee:attestation:001` missing nonce in post-boot attestation doc | `confirmed_candidate` | `true_positive` candidate | Source passes `nonce: None` while including manifest hash and public key. `user_data` binds state but does not provide verifier challenge freshness. Exploitability depends on how relying parties consume the attestation document. |
| `qos@df1e355:tee:attestation:002` unused attestation doc in `validate_manifest` | `confirmed_candidate` | `false_positive` | The report was misled by `#[allow(unused_variables)]`. In non-mock builds, `validate_manifest` calls `verify_attestation_doc_against_user_input` with the attestation doc, manifest hash, and PCR0-3. |
| `qos@df1e355:tee:attestation:006` unsafe timestamp extraction from NSM attestation doc | `confirmed_candidate` | `true_positive` candidate | Source requests an attestation doc with `nonce: None`, parses it with `unsafe_attestation_doc_from_der`, and returns only the timestamp. This is a real trust-boundary smell; severity depends on NSM/local-driver trust assumptions. |
| `qos@df1e355:tee:key_management:003` key injection caller binding | `needs_review` | `needs_context` | Requires RPC/transport call graph. |
| `qos@df1e355:tee:key_management:004` key export opaque authorization | `needs_review` | `false_positive` for the stated "missing implementation" reason | The implementation is visible in source and does use attestation doc in non-mock builds. Broader authorization may still need review. |
| `qos@df1e355:tee:boundary:005` NSM provider boundary assumptions | `needs_review` | `design_risk` | Trait abstraction and OS ACL assumptions should be documented, but this is not a proven vuln. |

Source checks:

- Missing nonce in attestation generation: <https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/attestation.rs#L23-L33>
- `validate_manifest` uses attestation doc in non-mock builds: <https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/key.rs#L143-L255>
- Timestamp extraction uses `unsafe_attestation_doc_from_der`: <https://github.com/tkhq/qos/blob/df1e355/src/qos_nsm/src/nsm.rs#L41-L54>

Scanner lesson: compile-time `cfg` blocks and conditional variable use must be
modeled. `#[allow(unused_variables)]` is not evidence that a parameter is
unused across all build configurations.

### Oasis SDK

Report/artifacts: `examples/oasis-sdk-scan/`

The only example with full stage artifacts already behaves conservatively:

- `boundary:002` is `no_issue_observed`.
- `boundary:001`, `boundary:003`, and `boundary:004` are `needs_review`.

Human review agrees that there is no confirmed vulnerability from the
available record. The targets are test runtime code and procedural macro
scaffolding, not direct runtime trust-boundary handlers. This example is useful
as a negative-control set for boundary overclassification.

## Scanner Quality Findings

The examples reveal recurring scanner failure modes:

1. Snippet truncation gets converted into vulnerability language.
   If the target symbol is not present in the packet, the only acceptable
   verdict is `needs_context`.

2. Low-level wrappers and parsers are treated as policy boundaries.
   A function that parses a quote or wraps an SGX/Nitro call is not required to
   enforce full attestation policy unless callers rely on it as such.

3. Protocol semantics are missing from the model.
   MobileCoin's `HandshakeNX` case shows that authentication expectations
   depend on protocol role, not just the presence of payload bytes.

4. Feature flags and build configuration are under-modeled.
   dcap-qvl's dangerous override is non-default; qos's `attestation_doc`
   appears unused only outside the relevant `cfg(not(feature = "mock"))` block.

5. Confirmed/corroborated labels are too strong.
   Many reports say "corroborated" when they only corroborate a code fact, not
   exploitability or violated security intent.

6. Outer validation flows are missed.
   Phala IAS is the clearest example: `verify_signature` is narrow, but
   `validate_ias_report` performs the omitted policy checks.

## Recommended Scanner Changes

1. Add a `human_verdict` benchmark fixture derived from this document.
   Store labels separately from scanner outputs so future runs can be scored.

2. Replace `confirmed_candidate` with narrower labels:
   `code_fact_confirmed`, `policy_gap_confirmed`, `exploitability_unproven`,
   and `true_positive_candidate`.

3. Require call-site evidence before claiming wrapper/parser vulnerabilities.
   A finding should identify at least one trust decision that consumes the
   wrapper/parser output without required policy checks.

4. Add explicit evidence completeness gates:
   if target symbol body is absent, if required helper body is absent, or if
   critical `cfg` branches are unknown, force `needs_context`.

5. Include build and feature context in findings:
   default features, danger/test features, and relevant `cfg` blocks should be
   captured before severity is assigned.

6. Track false-positive reason codes:
   `outer_validation_missed`, `protocol_semantics_missed`,
   `feature_flag_context_missed`, `cfg_context_missed`,
   `wrapper_policy_split`, `snippet_truncation`.

