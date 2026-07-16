# CodeQL build harness for TWE-CONFIG-0001

The fixture's `src/attest.rs` is self-contained (it defines its own Evidence,
Mode, and Error), so this skeleton is minimal: a Cargo.toml and a lib.rs that
declares `mod attest`. `codeql.AssembleFixtureCrate` overlays the variant's
`src/attest.rs` before `codeql database create`.
