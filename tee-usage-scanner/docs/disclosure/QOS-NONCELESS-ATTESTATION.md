# Disclosure draft — QOS-NONCELESS-ATTESTATION

**Channel**: Private GitHub Security Advisory (do **not** open as a public issue).
**Submit at**: https://github.com/tkhq/qos/security/advisories/new

## Form fields

- **Title**: Post-boot Nitro attestation document is generated without a verifier nonce, weakening replay resistance
- **Severity (tentative)**: Conditional on relying-party behavior. If replay leads to secret provisioning into a stale or unauthorized context: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1. Lower (and possibly not CVE-worthy) if timestamp + ephemeral-key binding fully prevent practical replay.
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay), CWE-345 (Insufficient Verification of Data Authenticity)
- **Affected product**: `tkhq/qos`
- **Affected versions**: to-be-confirmed (reviewed at commit `df1e355`)

## Description (paste into the body field)

### Summary

`get_post_boot_attestation_doc` in `src/qos_core/src/protocol/services/attestation.rs` constructs a Nitro attestation request with `nonce: None`. The request includes the manifest hash (`user_data`) and the ephemeral public key, but no verifier-supplied challenge. Without a fresh challenge bound into the signed document, a relying party that does not enforce strict timestamp/freshness checks against a trusted clock cannot distinguish a freshly-generated attestation document from a captured-and-replayed document for the same manifest.

### Affected component

- File: `src/qos_core/src/protocol/services/attestation.rs`
- Functions: `live_attestation_doc`, `get_post_boot_attestation_doc`
- Permalink (reviewed commit): https://github.com/tkhq/qos/blob/df1e355/src/qos_core/src/protocol/services/attestation.rs#L23-L33

Related reviewed links:

- `verify_attestation_doc_against_user_input` rejects a present nonce: https://github.com/tkhq/qos/blob/df1e355/src/qos_nsm/src/nitro/mod.rs#L67-L148
- `proxy_re_encrypt_share` verifies the attestation document and extracts the ephemeral public key: https://github.com/tkhq/qos/blob/b2ea15b/src/qos_client/src/cli/services.rs#L1239-L1291
- `attestation_doc_from_der` verifies the certificate chain and COSE signature: https://github.com/tkhq/qos/blob/b2ea15b/src/qos_nsm/src/nitro/mod.rs#L186-L221

### Technical detail

```rust
NsmRequest::Attestation {
    user_data: Some(manifest_hash),
    nonce: None,
    public_key: Some(ephemeral_public_key),
}
```

`user_data` binds the document to manifest state, and `public_key` binds it to an ephemeral key, but neither field carries verifier-side freshness.

### Security impact

If a relying party accepts a Nitro attestation document as proof of "live enclave instance now" without:

- enforcing a challenge nonce of its own choosing, or
- enforcing a strict timestamp validity window using a trusted clock,

then a previously-captured valid document for the same manifest can be replayed during provisioning or post-boot verification.

Practical exploitability depends on relying-party behavior:

- If the ephemeral public key is freshly generated on every boot and never reused, and the relying party only encrypts to that attested public key, a replayed document binds the wrong key and the attack collapses.
- If any relying-party flow trusts the document for state that does not depend on the ephemeral key, replay risk is real.

### Relying parties identified

A code-level audit of relying-party verification (current `main`, commit `b2ea15b`) reaches the same body of behavior as `df1e355`. All four `verify_attestation_doc_against_user_input` call sites live in `src/qos_client/src/cli/services.rs`:

- `services.rs:487` — genesis ceremony output verification
- `services.rs:666` — `after_genesis`, before re-reading attestation doc from disk
- `services.rs:1166` — `boot_standard`, after the client receives `BootStandardResponse`
- `services.rs:1267` — **`proxy_re_encrypt_share`**, the secret-release path: after this verification the member re-encrypts their quorum share to the ephemeral public key extracted from the attestation document (`services.rs:1267-1289` and the re-encryption that follows)

The key security property of this path is that the share is released to the public key carried in the attestation document. If the document is stale and the attacker retained the corresponding private key, replay has a concrete consequence.

The verifier itself, `verify_attestation_doc_against_user_input` in `src/qos_nsm/src/nitro/mod.rs:67-148`, performs:

- exact match of `user_data`,
- exact match of `pcr0`, `pcr1`, `pcr2`, `pcr3`,
- **explicit rejection of any nonce being present in the document** (`AttestError::UnexpectedAttestationDocNonce` at line 88-90).

The verifier does **not** check the attestation document's own `timestamp` field, and does not require a challenge. The only freshness gate is the AWS Nitro end-entity certificate validity window enforced by `attestation_doc_from_der` via `webpki::Time::from_seconds_since_unix_epoch(validation_time)` (`mod.rs:241`), where `validation_time` is `SystemTime::now()` by default (`services.rs:2199-2206`). This validates certificate chain freshness, not document freshness; the AWS Nitro EE certificate window is on the order of three hours.

Because the verifier explicitly rejects a present nonce, **a fix that only adds a nonce to `get_post_boot_attestation_doc` would break all four relying parties** — both sides of the contract have to change together.

### Practical attack scenario

The strongest replay path is `proxy_re_encrypt_share`:

1. Attacker previously controlled, or had access to, a legitimate enclave instance with PCRs matching the target manifest, and retained the ephemeral private key from that instance.
2. Within the AWS Nitro EE certificate validity window (~3 hours), the attacker obtains or replays a valid post-boot attestation document originally generated by that prior instance.
3. The attacker is positioned between the client and the live enclave (or otherwise serves the captured document to the relying party).
4. The relying party calls `verify_attestation_doc_against_user_input`. PCRs match (same manifest), `user_data` matches (same manifest hash), no nonce is checked, the cert chain is still within its validity window. Verification passes.
5. The client re-encrypts the quorum share to the ephemeral public key embedded in the replayed document, which the attacker still holds the private key for.

This requires alignment of (a) cert window, (b) a prior instance with a matching manifest, and (c) retained ephemeral private key from that instance — all real but non-trivial. The window can be reduced (but not closed) by faster cert rotation; only a verifier-supplied challenge fully closes it.

### Severity, refined

Conditional on the above: the secret-release path in `proxy_re_encrypt_share` is real and is the kind of flow CVE-294 captures. We are happy to coordinate on a PoC harness if it would help the maintainers triage.

### Reproduction plan

PoC pending relying-party identification. Skeleton:

1. Capture a valid post-boot attestation document for a given manifest.
2. Replay it in a later provisioning / verification flow against the same relying party.
3. Show acceptance without a fresh challenge.
4. Demonstrate a concrete consequence — for example, secret release into a stale instance.

### Suggested fix

The fix has to be applied to both sides of the contract in the same release:

- Plumb a verifier-provided nonce / challenge into `live_attestation_doc` and `get_post_boot_attestation_doc`, and pass it into `NsmRequest::Attestation`.
- Update `verify_attestation_doc_against_user_input` to **require** a nonce, replacing the current "reject if present" branch with "reject if absent or unequal to expected challenge".
- Update all four call sites in `qos_client/cli/services.rs` (lines 487, 666, 1166, 1267) to generate and pass a challenge.
- Optionally also start enforcing the attestation document's own `timestamp` field against a freshness window (independent of cert chain validity).
- Keep `user_data` and `public_key` binding for state binding, but do not treat them as freshness substitutes.

## Pre-submission checklist

- [x] Relying parties identified (4 sites in `qos_client/cli/services.rs`).
- [x] Verifier behavior confirmed (`verify_attestation_doc_against_user_input` rejects present nonces and does not check doc timestamp).
- [x] Behavior re-confirmed on current `main` (commit `b2ea15b`); the same code shape persists from `df1e355`.
- [ ] Confirm affected version range with the maintainer (anchor commit `df1e355`, still present on `main` as of `b2ea15b`).
- [ ] Decide whether to attach a replay PoC for the `proxy_re_encrypt_share` path. A PoC is the deciding factor between "design risk" and "CVE-grade".
- [ ] Decide on credit / handle for the security advisory.
- [ ] Pick a disclosure window (90 days is the common default; longer if no PoC is attached).
