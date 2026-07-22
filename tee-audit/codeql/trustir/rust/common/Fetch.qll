/**
 * Fetch.qll (Rust)
 *
 * Repo-wide ENUMERATION helpers for the LLM-classification ("fetch") queries.
 * Pure-deterministic, LLM-free: deny-list globs for paths that must NOT be
 * enumerated because they are vendored, generated, or build artifacts.
 *
 * Mirrors the Go pack's exclusion semantics but is Rust-specific:
 *   - `target/`         — cargo build output (often huge, never source of truth)
 *   - `vendor/`         — vendored third-party crates (Go-style)
 *   - `cargo-home/registry/` — cargo's downloaded crate cache (the Rust analog
 *     of `vendor/`; appears under the audit artifact dir's `cargo-home/`)
 *   - `cargo-target/`   — out-of-tree cargo target dir used by the audit harness
 *   - `.rustup/toolchains/` — Rust standard-library sources (~/.rustup/...),
 *     picked up by the Rust extractor but not part of the audited project
 *   - `build/`          — generic out-of-tree build dirs
 *   - `generated/`      — explicit generated-code directories
 *   - `testdata/`, `fixtures/` — test-fixture data (not real runtime code)
 *   - `*.pb.rs`         — protobuf-generated bindings (Rust convention)
 *
 * Per Decision-R, rust-all 0.2.4 has NO `hasQualifiedName` and NO
 * `getDeclaringType`, so enumeration is by NAME + SIGNATURE + LOCATION ONLY.
 * The exclusion below is therefore purely path-based, matched on the file's
 * absolute or repo-relative path.
 *
 * Provides module `Fetch` with:
 *   - excludedFromEnumeration(File f)
 */

import rust
import codeql.files.FileSystem

module Fetch {
  /**
   * Holds when `f` lives under a vendored / generated / build / test-fixture
   * path and must be skipped by every enumeration query. Matching is on the
   * file's absolute path, so it works regardless of how the database's
   * source-root is laid out.
   */
  predicate excludedFromEnumeration(File f) {
    f.getAbsolutePath().matches("%/vendor/%") or
    f.getAbsolutePath().matches("%/target/%") or
    f.getAbsolutePath().matches("%/build/%") or
    f.getAbsolutePath().matches("%/generated/%") or
    f.getAbsolutePath().matches("%/testdata/%") or
    f.getAbsolutePath().matches("%/fixtures/%") or
    // Cargo's downloaded third-party crate cache (the Rust analog of Go's
    // `vendor/`). The real path is ~/.cargo/registry/src/index.crates.io-.../
    // (US-003 guessed "cargo-home/registry"; the actual dir is ".cargo/registry").
    // Without this, Rust macro-expanded dep crates (serde/darling/syn/...) flood
    // the enumeration (~370K functions vs ~1.4K own-code in dcap-qvl).
    f.getAbsolutePath().matches("%/.cargo/registry/%") or
    f.getAbsolutePath().matches("%/cargo-home/registry/%") or
    // Out-of-tree cargo target dir used by the audit harness.
    f.getAbsolutePath().matches("%/cargo-target/%") or
    // Rust standard-library sources picked up from the toolchain (~/.rustup/).
    // NB: the directory is `.rustup` (hidden), so the glob must include the dot.
    f.getAbsolutePath().matches("%.rustup/toolchains/%") or
    // CodeQL's own Rust builtins/tools source (shipped with the CLI).
    f.getAbsolutePath().matches("%/codeql/rust/tools/%") or
    // Protobuf-generated Rust bindings (Rust convention: *.pb.rs).
    f.getBaseName().matches("%.pb.rs")
  }
}
