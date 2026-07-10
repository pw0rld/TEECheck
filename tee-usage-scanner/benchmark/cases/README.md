# Executable Benchmark Cases

Each case contains exact vulnerable and fixed upstream source files, an exact
security patch, immutable revision identifiers, file hashes, and a reviewed
oracle. The fixtures are source subsets intended for scanner evaluation; they
are not standalone OP-TEE build trees.

Current cases:

- `CVE-2022-46152`: normal-world parameter count causes secure-world OOB access.
- `CVE-2023-41325`: partial RSA allocation failure produces a double free.
- `CVE-2025-46733`: crashed keep-alive TA restart resets trusted state.

Validate provenance and structure from the module root:

```sh
go run ./benchmark/runner
go test ./benchmark/runner
```

Validation does not execute TEECheck or score findings yet. Cases remain
excluded from benchmark metrics until the scanner adapter and result comparator
produce a normalized verdict for both sides of each pair.
