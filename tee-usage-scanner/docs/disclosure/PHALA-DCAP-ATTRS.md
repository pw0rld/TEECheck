# Disclosure draft — PHALA-DCAP-ATTRS

**Channel**: Private GitHub Security Advisory (do **not** open as a public issue).
**Submit at**: https://github.com/phala-network/phala-blockchain/security/advisories/new

## Form fields

- **Title**: SGX attestation trust policy omits `misc_select` and `attributes` checks — debug enclaves may be accepted as trusted
- **Severity (tentative)**: High if this verifier output or runtime identity / allowlist key is used for production worker admission, key handover, or another trust decision — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1. Reduce severity if production paths have migrated, debug builds cannot satisfy the allowlist, or downstream code independently enforces attribute policy.
- **CWE**: CWE-295 (Improper Certificate Validation), CWE-345 (Insufficient Verification of Data Authenticity), CWE-693 (Protection Mechanism Failure)
- **Affected product**: `phala-network/phala-blockchain`
- **Affected versions**: to-be-confirmed (reviewed at commit `654b1b6`; please confirm whether `main` and the latest released tag still exhibit this behavior)

## Description (paste into the body field)

### Summary

The SGX DCAP verifier in `crates/sgx-attestation/src/dcap.rs` performs collateral, certificate-chain, and signature checks, but explicitly skips validation of the SGX report's `misc_select` and `attributes` fields. More broadly, the pRuntime trust identity / allowlist key appears to be constructed from `mr_enclave`, `isv_prod_id`, `isv_svn`, and `mr_signer`, while omitting `attributes` and `misc_select`. We observed this identity shape in the DCAP path, IAS-derived path, legacy IAS path, and local-attestation-based handover checks.

An enclave whose measurement / signer identity is present in the production allowlist, but whose runtime configuration violates policy (for example, `ATTRIBUTES.flags & SGX_FLAGS_DEBUG` is set), may therefore be accepted as a trusted worker if no downstream policy check rejects those attributes.

### Affected component

- Primary file: `crates/sgx-attestation/src/dcap.rs`
- Primary function: `verify`
- Primary permalink (reviewed commit): https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-attestation/src/dcap.rs#L27-L53

Related paths where the same runtime identity shape appears:

- `pallets/phala/src/utils/attestation.rs::validate_dcap`
- `pallets/phala/src/utils/attestation.rs::IasFields::extend_mrenclave`
- `pallets/phala/src/utils/attestation_legacy.rs::IasFields::extend_mrenclave`
- `crates/phactory/src/prpc_service.rs::measurement_of`
- `crates/sgx-api-lite/src/lib.rs::verify`

Reviewed permalinks:

- `validate_dcap`: https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L205-L264
- `IasFields::extend_mrenclave`: https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation.rs#L102-L109
- legacy `IasFields::extend_mrenclave`: https://github.com/phala-network/phala-blockchain/blob/654b1b6/pallets/phala/src/utils/attestation_legacy.rs#L97-L104
- `measurement_of`: https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/phactory/src/prpc_service.rs#L2312-L2322
- `sgx_api_lite::verify`: https://github.com/phala-network/phala-blockchain/blob/654b1b6/crates/sgx-api-lite/src/lib.rs#L102-L123

### Technical detail

The `verify` function contains explicit comments documenting the skipped checks:

```rust
// Seems we verify MR_ENCLAVE and MR_SIGNER is enough
// skip verify_misc_select_field
// skip verify_attributes_field
```

After the collateral / cert / signature path, the function constructs a `pruntime_hash` from `mr_enclave`, `isv_prod_id`, `isv_svn`, and `mr_signer`, but never enforces an `attributes` mask (e.g. rejecting `SGX_FLAGS_DEBUG`) or a `misc_select` policy.

The outer DCAP validation path in `pallets/phala/src/utils/attestation.rs::validate_dcap` calls `sgx_attestation::dcap::verify`, then checks:

- whether `pruntime_hash` is present in `pruntime_allowlist`;
- whether `report_data[..32]` matches the expected `user_data_hash`;
- whether `tcb_status` and `advisory_ids` map to an accepted confidence level.

We did not observe a compensating `attributes` or `misc_select` policy check in this outer path.

The same omission appears in the IAS-derived identity model. `crates/sgx-attestation/src/ias.rs::EnclaveQuoteBody` parses both `misc_select` and `attributes`, but `pallets/phala/src/utils/attestation.rs::IasFields` retains only `mr_enclave`, `mr_signer`, `isv_prod_id`, `isv_svn`, `report_data`, and `confidence_level`. `IasFields::extend_mrenclave()` then constructs the allowlist key only from:

```rust
mr_enclave || isv_prod_id || isv_svn || mr_signer
```

The legacy IAS path in `pallets/phala/src/utils/attestation_legacy.rs` uses the same `extend_mrenclave()` shape.

The pRuntime key-handover code also appears to reuse this identity model. `crates/phactory/src/prpc_service.rs::measurement_of(report)` builds a runtime measurement from local attestation report fields `mr_enclave`, `mr_signer`, `isv_prod_id`, and `isv_svn`, but not `report.body.attributes` or `report.body.misc_select`. `sgx_api_lite::verify(report)` verifies the local report MAC, but it does not enforce production enclave attribute policy.

### Security impact

If a caller submits an attestation whose measurement passes allowlist checks but whose `attributes.flags` includes DEBUG (or other forbidden bits), the verifier / runtime identity may still be accepted and downstream callers may treat the enclave as production-trusted. Realized impact depends on:

- whether this verifier output is consumed by production worker-admission / trust-decision code;
- whether the same runtime identity is reused for IAS-derived or local handover decisions;
- whether downstream callers independently enforce `attributes` / `misc_select` policy;
- whether any `mr_enclave` / `mr_signer` already in the allowlist can also be produced as a debug build with a verifiable signing identity.

If those conditions hold, this is an attestation-policy bypass.

### Reproduction plan

PoC has not been built against a live Phala deployment yet. Skeleton:

1. Obtain or generate a DCAP quote whose `mr_enclave` / `mr_signer` are present in the worker allowlist, but whose `attributes.flags` has DEBUG set.
2. Submit the quote and collateral to `verify`.
3. Observe that verification succeeds.
4. Confirm that the returned `ConfidentialReport`, `pruntime_hash`, or derived runtime identity is consumed by the trust path without further attribute validation.
5. Repeat the same policy check against any IAS-derived or local handover path that uses the same allowlist identity.

We are happy to coordinate on a private fixture if helpful.

### Suggested fix

- Add explicit policy checks for `misc_select` and `attributes` (with masks), mirroring Intel DCAP / QVL policy validation.
- Reject DEBUG enclaves in production unless explicitly enabled by configuration.
- Include `attributes` / `misc_select` in the pRuntime trust identity, or enforce them immediately before any allowlist lookup.
- Add negative-fixture tests for the debug bit and unexpected attribute bits.
- Add tests for both DCAP and IAS-derived report bodies, and for any local-attestation handover path that relies on `measurement_of(report)`.
- Document any deliberately allowed non-default attributes.

### Pre-disclosure questions

- Is this verifier the production worker-admission path, or has it been superseded by a newer attestation stack?
- Are debug enclaves ever explicitly allowed in production via configuration?
- Is `PRuntimeAllowList` intended to authorize only measurement / signer identity, or the full production enclave configuration?
- Does any downstream code independently enforce `attributes` and `misc_select` policy for DCAP, IAS-derived, legacy IAS, and local handover flows?
- Should `attributes` / `misc_select` be included in the runtime hash or checked before looking it up?
- Which release first shipped the skipped checks and the current runtime identity shape, and is the behavior still present on `main`?

## Pre-submission checklist

- [ ] Confirm affected version range, or note it as a question for the maintainer in the body.
- [ ] Re-check that the permalink lines still exist on commit `654b1b6` and on `main`.
- [ ] Re-check on current `main` whether `validate_dcap`, `extend_mrenclave`, and `measurement_of` still use the same field set.
- [ ] Decide whether to attach a PoC quote. For this finding, a PoC quote materially changes how the maintainer triages — building one before disclosure strengthens the report.
- [ ] Decide on credit / handle for the security advisory.
- [ ] Pick a disclosure window (90 days is the common default; longer if no PoC is attached).
