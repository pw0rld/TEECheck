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
