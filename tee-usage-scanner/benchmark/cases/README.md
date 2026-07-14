# Executable Benchmark Cases

Each case contains exact vulnerable and fixed upstream source files, an exact
security patch, immutable revision identifiers, file hashes, and a reviewed
oracle. The fixtures are source subsets intended for scanner evaluation; they
are not standalone OP-TEE build trees.

The full list is in [INDEX.md](INDEX.md). The current corpus contains 68 cases:
50 executable source cases and 18 pending-source candidates.

Examples of executable cases include:

- `CVE-2019-1010292`: registered-memory subrange is not bounded by its MOBJ.
- `CVE-2019-1010293`: unaligned range can skip final-page access validation.
- `CVE-2019-1010294`: TA allocation tail is not cleared before memory reuse.
- `CVE-2019-1010295`: user TA pointers reach pseudo TAs without access checks.
- `CVE-2019-1010296`: crypto object attribute allocation can integer-overflow.
- `CVE-2019-1010297`: key generation/derivation allocation can integer-overflow.
- `CVE-2019-1010298`: asymmetric operation allocation can integer-overflow.
- `CVE-2023-37479`: SGX entry does not sanitize `MXCSR` and `RFLAGS.AC`.
- `CVE-2020-15224`: socket syscalls do not safely validate host-controlled boundary data.
- `CVE-2020-15107`: SGX entry does not clear host-controlled extended FPU state.
- `CVE-2021-32032`: multipart Crypto abort cleanup is ineffective.
- `CVE-2023-40271`: ChaCha20-Poly1305 compares a partial authentication tag.
- `CVE-2024-45746`: mailbox validation failure can write back input vectors.
- `CVE-2022-46152`: normal-world parameter count causes secure-world OOB access.
- `CVE-2023-41325`: partial RSA allocation failure produces a double free.
- `CVE-2025-46733`: crashed keep-alive TA restart resets trusted state.

Validate provenance and structure from the module root:

```sh
go run ./benchmark/runner
go test ./benchmark/runner
```

Run TEECheck against both sides of every pair and score the results:

```sh
go run ./benchmark/runner \
  -mode evaluate \
  -results benchmark/results/teecheck \
  -timeout 45m \
  -scanner-command '. ./.env.local; go run ./cmd/teecheck run {input} --mode llm --focus tee --run-id scan --output-dir {run_dir} --knowledge-root knowledge --max-cases 8 --max-hotspots 8'
```

The command template supports `{input}`, `{run_dir}`, `{case}`, and `{variant}`.
The runner executes it once for each vulnerable and fixed tree, locates the
single generated `findings.json`, matches it against the case oracle, and writes
`score.json` under the selected results directory.

Score previously generated results without rerunning the scanner:

```sh
go run ./benchmark/runner -mode score -results benchmark/results/teecheck
```

The scorer requires both the primary file and semantic evidence such as the
vulnerable function or case-specific terms. An unrelated finding in the same
file does not satisfy the oracle.

## Classification

- Vulnerable side matches: true positive (`TP`).
- Vulnerable side does not match: false negative (`FN`).
- Fixed side matches the same oracle: false positive (`FP`).
- Fixed side does not match: true negative (`TN`).
- A case passes as a pair only when it is `TP + TN`.

The report includes precision, recall, F1, specificity, and paired pass rate.
