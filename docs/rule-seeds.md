# TEE×Web3 Rule Seeds

Not every seed is a taint rule. Map each seed to the right analysis family.

## Flow-oriented seeds

1. Secrets, plaintext, attestation blobs, or decrypted state reach logs or telemetry.
2. Host-controlled config, time, or storage metadata reaches a trusted decision.
3. Untrusted artifact input reaches key release, admission, or policy update without sanitizing or validation.

## Guard-oriented seeds

4. Attestation acceptance reaches validator admission, peer acceptance, or key release without all required guards.
5. Recovery, migration, or upgrade paths bypass normal attestation or policy checks.
6. Policy-changing surfaces exist without explicit caller authentication or authorization.

## Binding-oriented seeds

7. Measurement, signer, PCR, or version fields are only partially checked before trusted admission.
8. Report data does not bind the attested key, challenge, or output to the verified evidence.
9. Off-chain worker output reaches on-chain or cross-service acceptance without chain, network, or identity binding.

## State/lifecycle seeds

10. Restored or sealed state is not bound to epoch, network, version, or continuity metadata.
11. Replayable trust statements or stale authorization artifacts can be reused across sessions or restarts.
12. Clone or rollback assumptions exist without a corresponding monotonicity or continuity defense.

## Config/build/deployment seeds

13. Debug, simulation, or dev mode reaches production launch or admission paths.
14. Helper wrappers hide relaxed verification, feature-gated bypasses, or environment-dependent trust assumptions.
