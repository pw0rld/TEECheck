# M2 CodeQL Spike — Result: PASS

**Date:** 2026-07-14
**Question:** Can CodeQL build a Rust database in this environment and can a
prewritten TWE query distinguish a vulnerable revision from its fix by SARIF —
i.e. is the deterministic TWE spine viable before we invest in M3–M5?

**Answer:** Yes, end to end.

## Environment

| Component | Version | Notes |
|---|---|---|
| CodeQL | 2.26.0 (bundle) | `rust` extractor present in `codeql resolve languages` |
| Rust QL library | `codeql/rust-all` 0.2.16 | full AST + dataflow libraries |
| Rust queries | `codeql/rust-queries` 0.1.37 | ships security suites |
| Rust toolchain | rustc/cargo 1.97.0 | required: the Rust extractor builds via cargo |

Installed under `/root/codeql-home/codeql` and `~/.cargo`. ~3 GB on disk.

## What was proven

Two compilable cargo crates were built from the `TWE-BIND-0001` fixture — a
vulnerable and a fixed `register_worker` that differ only in whether authority
is bound to the attested key (`report.pubkey`).

1. **Rust DB build works.** `codeql database create --language=rust` produced a
   database for each variant (~38 MiB relations) with no manual build config
   beyond a standard `Cargo.toml`.
2. **A prewritten TWE query runs and discriminates.**
   `binding/missing_subject_binding.ql` flags a function that calls
   `verify_quote` but never references the attested `pubkey` field.
3. **SARIF output distinguishes vuln from fixed** — the format the Solver will
   consume:

   | Variant | SARIF results | Location |
   |---|---|---|
   | vulnerable | **1** | `src/registry.rs:8` (`fn register_worker`) |
   | fixed | **0** | — |

The verdict comes from a code fact (is the attested field referenced on the
authority path), not from LLM prose. Swapping the model would not change it.

## Reproduce

```sh
export PATH="/root/codeql-home/codeql:$HOME/.cargo/bin:$PATH"
# for each variant crate <dir>:
codeql database create db-<v> --language=rust --source-root=<dir> --overwrite
codeql database analyze db-<v> codeql/queries/binding/missing_subject_binding.ql \
  --format=sarifv2.1.0 --output=<v>.sarif --rerun
```

## Caveats / follow-ups (M2-proper, not the spike)

- The seed query is a **first-cut syntactic heuristic** ("calls verify_quote and
  no `pubkey` field access"). M4 replaces it with a real dataflow query: no
  accepted binding relation from `claim_field` to `authority_subject`.
- **Pack dependency resolution**: `codeql/rust-all` pulls transitive packs
  (e.g. `codeql/namebinding`) that are vendored inside the bundle's
  `rust-queries` pack but not resolvable by a bare custom pack without a lock
  file. M2-proper must wire `teecheck/twe-queries` to resolve against the
  bundle (lock file or `--additional-packs`), then invoke via the Go adapter.
- **DB build needs a compilable crate.** Real targets (dcap-qvl) build fine;
  single-file fixtures need a minimal `Cargo.toml` wrapper. The benchmark
  fixtures will need a build shim for the Rust path.
- CodeQL adapter in `internal/staticcheck/codeql` is still a stub
  (`Available()==false`); wiring it to a real `codeql` invocation + SARIF
  parser is the M2 implementation task.

## Decision

The deterministic spine is viable. Proceed to build M2 (CodeQL fact engine:
DB build, analyze, SARIF parser, fail-fast diagnostics) → M3 (Binder) → M4
(query generation) → M5 (Solver).
