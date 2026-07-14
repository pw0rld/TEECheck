# CodeQL build harness for TWE-BIND-0001

CodeQL's Rust extractor builds a database by compiling the crate, but the
benchmark fixture ships only the single patched file (`src/registry.rs`). This
directory is the minimal compilable crate skeleton that file needs: a
`Cargo.toml`, a `lib.rs` module tree, and stub modules for anything the scan
file imports (here, `attest`).

To build a database for a variant, overlay the variant's `scan_paths` on top of
this skeleton, then run `codeql database create --language=rust`. The Go helper
`codeql.AssembleFixtureCrate` does the overlay; see the M2 integration test.
