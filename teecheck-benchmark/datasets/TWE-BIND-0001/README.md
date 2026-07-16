# TWE-BIND-0001 (synthetic)

Synthetic Binding fixture. A DCAP-style `register_worker` verifies an
attestation quote but grants authority to the caller-supplied `pubkey`
instead of the attested `report.pubkey`, so a valid quote can be replayed
to register an attacker-controlled key. The fixed revision binds authority
to the attested key. Not a public CVE; models the TWE Binding family
(missing subject binding) that the CVE corpus does not cover.
