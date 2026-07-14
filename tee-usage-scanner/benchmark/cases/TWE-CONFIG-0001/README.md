# TWE-CONFIG-0001 (synthetic)

Synthetic Config fixture. `verify_attestation` accepts `Mode::Simulated`
evidence unconditionally, and the simulation branch is compiled into every
build, so production can be fed simulated evidence and skip all real DCAP
verification. The fixed revision gates the simulation branch behind a
compile-time feature and rejects it otherwise. Not a public CVE; models the
TWE Config family (weak/simulation mode reaching authority).
