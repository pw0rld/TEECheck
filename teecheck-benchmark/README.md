# TEECheck Benchmark

This directory contains the executable source fixtures, evaluation runner, and
reviewable score reports used to measure TEECheck.
The scanner's current execution and evidence contracts are documented in
[HARNESS.md](../tee-usage-scanner/docs/HARNESS.md) and
[CONTRACTS.md](../tee-usage-scanner/docs/CONTRACTS.md).

## Directory Layout

### `datasets/`

Executable benchmark cases. Each case represents one vulnerability and contains
an exact vulnerable/fixed source pair:

```text
datasets/CVE-YYYY-NNNN/
├── case.yaml          # Repository, revisions, scan paths, and file hashes
├── oracle.yaml        # Vulnerability location, trigger, required evidence,
│                      #   TWE scope, oracle_review provenance, leakage_suspect
├── vulnerable/        # Source before the security fix
├── fixed/             # Source after the security fix
├── patches/fix.patch  # Exact upstream security patch
├── UPSTREAM-LICENSE   # optional copy of the upstream license text
└── README.md
```

There are 44 stored source pairs. **43 are executable (86 scan samples)**;
`CVE-2019-1010297` is marked `fixture_status: requires_review` and excluded
because a fix hunk does not match either stored variant. The other 43 have
`fixture_status: ready`. Validation checks hashes and patch direction, so a
reversed vulnerable/fixed pair cannot silently score. See the
[2026-11-21 review](reports/2026-11-21-oracle-review.md).

Every case is source-backed: it pins a public CVE (`detection_surface:
source`) with a real upstream repository, revisions, and record. Hand-authored
synthetic fixtures are not admitted — the benchmark measures detection of real,
public vulnerabilities.

The corpus includes TEE-internal defects in trusted OSes, secure firmware, and
enclaves, plus explicitly classified controls in generic libraries or adjacent
Linux code. Those controls remain outside the capability track; their presence
must not be mistaken for support of all software or hardware attack classes.

Each reviewed `oracle.yaml` also carries a TWE scope classification so the
benchmark measures "can we find the CVEs we are designed to find" instead of
penalising the scanner for weaknesses it was never meant to reach:

```text
twe_family    # Flow | Guard | Binding | State | Config | Design | Leakage, or "" if out of scope
in_twe_scope  # true when twe_family != "" (derived, kept in sync by the validator)
case_kind     # vulnerability | hardening (defensive-hardening commits are flagged, not hidden)
scope_reason  # one-line justification for the family / out-of-scope decision
```

Two further fields record how much each oracle can be trusted, because a
fix-commit-derived oracle is noisy (ISSTA'25 "Top Score on the Wrong Exam"
found 20-71% of vulnerable labels in the most-used datasets are wrong):

```text
oracle_review.location_provenance
  # single-file-fix       the fix touched one file — primary_file is unambiguous
  # multi-file-confirmed  multi-file fix, primary_file reviewed as the exploitable file
  # multi-file-corrected  multi-file fix, primary_file was moved off collateral to the real file
  # multi-file-pending    multi-file fix, not yet reviewed (none currently)
oracle_review.patch_files # how many files the fix patch touches (ripple indicator)
leakage_suspect           # every case pins a public CVE plausibly in the GLM
                          #   training corpus, so this is true for all of them
```

`primary_function` and `match_terms` are retained as review evidence only.
They are **not** used for scoring — the matcher scores on file + TWE family (see
the runner section) — and several `primary_function` values name the point the
weakness is *reached* rather than the line the fix changed.

A case is **in TWE scope** when detecting it requires reasoning about a TEE
trust relationship (untrusted↔trusted boundary data flow, attestation or
signature validity, secret leakage, state rollback, or a debug/simulation
config reaching production). It is **out of scope** when it is a generic
memory-safety, arithmetic, resource, or concurrency bug that a sanitizer or
fuzzer catches without any TEE-specific semantics. Out-of-scope cases are a
known coverage gap of the TWE design, not a scanner failure.

The source-and-patch review classified all 44 stored pairs: **25 in scope,
19 outside the current TWE threat model**. All 25 in-scope pairs are executable;
18 out-of-scope pairs are executable and one requires source review. In-scope
families are Flow 13, Guard 7, State 3, Binding 1, and Leakage 1. Config and
Design remain uncovered. `scope_reason` and `oracle_review.scope_review` explain
each inference with the local source site and patch; these annotations are not
a claim of independently reproduced exploitation.

Pure arithmetic memory defects, physical fault injection, low-level timing
side channels, and general-purpose non-TEE libraries stay in the secondary
track. Every public-CVE pair is labeled `leakage_suspect: true`. These known
cases cannot alone demonstrate discovery of unseen bugs.

### `evaluator/runner/`

The Go evaluator used to validate fixtures, invoke a scanner, read TEECheck
`findings.json`, compare findings with each case oracle, and calculate metrics.

Supported modes:

- `validate`: verify case metadata, source hashes, patches, and oracle structure.
- `evaluate`: scan every vulnerable/fixed pair and then score the results.
- `score`: score previously generated scanner results without rerunning scans.

The evaluator reports TP, FP, FN, TN, precision, recall, F1, specificity, and
paired pass rate on three tracks — `overall`, `in_twe_scope`, and
`out_of_twe_scope` — plus a per-family breakdown of the in-scope track.
**Read scanner capability off the `in_twe_scope` track**; the overall track
dilutes it with out-of-scope cases the TWE pipeline does not target. A case
passes only when the vulnerable side is detected and the fixed side is not
reported as the same vulnerability.

A finding matches an oracle by the mechanism established by OWASP Benchmark and
NIST Juliet/SARD: **location plus weakness class**. It must land on the oracle's
`primary_file` **and** assert the oracle's `twe_family` — the family the scanner
carries in its explicit `related_twes` metadata. Legacy findings without that
field may fall back to the `TWE-<FAMILY>-NNN:...` identifier. Class agreement, not free-text keyword overlap, is what counts; earlier
`match_terms` string matching both inflated true positives (an unrelated finding
that merely mentioned the file) and missed correct prose that used different
words. `match_terms` and `primary_function` are retained in the oracle as
human-review evidence only; they no longer gate scoring. Out-of-scope cases
(empty `twe_family`) have no expected class and are matched on file alone, on
their separate secondary track. Site matching uses `primary_line` with a tolerance of ±12 lines when the
finding supplies a line on the primary file. `primary_symbols` is a fallback
when no exact source line is available; a matching symbol never overrides a
conflicting line elsewhere in the same function. All stored cases now carry
a reviewed line and a symbol list (empty for the build-file case).

Scores separate `target_observed` from `incidental_count`: a fixed-side TN can
still contain unrelated findings, and the Markdown/JSON reports show both.
A report with zero classified in-scope cases emits an explicit warning. Use
`-require-in-scope` in evaluate/score mode to reject that selection entirely.

### Attempt isolation and integrity gate

Each `evaluate` invocation creates a new attempt for each source variant:

```text
results/<case>/<variant>/
├── latest.json
└── attempts/attempt-<unique>/
    ├── attempt.json
    └── <scanner-run>/
        ├── 00_manifest.json
        ├── events.jsonl
        └── 07_arbiter/findings.json
```

`latest.json` is replaced before the scanner starts. A crashed or failed new
attempt therefore cannot fall back to a successful older result. `attempt.json`
records start/end timestamps, exit status, the exact output directory and the
scanner's offline `validate-run` result. Score mode reads only the selected
attempt and revalidates its bundle; old loose `findings.json` files, nonzero
scanner exits, stale timestamps, wrong repository/revision, missing stages,
corrupt blobs, and invalid contract/assessment links are `ERROR`, never TN/FN.
Existing raw historical results remain on disk but are not formal scores.

The benchmark imports the scanner's public `runbundle` wrapper to reuse the
actual validator. Both modules therefore use Go 1.25; no second copy of the
integrity rules is maintained. Run manifests record `expected_stages` and
`source_scope_mode` (`pinned_checkout` or `local_fallback`). The preprocessor's
knowledge output remains optional for custom knowledge roots; its stage events
are mandatory. New typed contracts, assessments, and findings must agree on
case, invariant ID, definition hash, scope and source evidence.

When a valid run emits no findings but reconnaissance is incomplete or its
index explicitly reports partial coverage, the variant is
`INCOMPLETE_COVERAGE`. It is counted separately from errors and TP/FP/FN/TN;
metrics with no scored variants are unavailable. `origin_counts` and
`target_origin_counts` distinguish `planner`, `deterministic`, `both`, and
legacy `unknown`, so a deterministic control is not presented as autonomous
planner discovery.

`--samples` remains one run's coverage expansion. Re-running `evaluate` creates
new independent attempts, but `score` selects the latest attempt for each
variant; it does not pretend a multi-sample run is a repeat-stability study.

On Unix, each scanner command starts in its own process group. Cancellation or
timeout sends `SIGKILL` to that group, including the shell and descendants that
retain the group; inherited output pipes have a bounded wait. Normal completion
also cleans up remaining processes in that group. A descendant that deliberately
creates a new session or process group can escape this mechanism and needs OS
containment if stronger isolation is required. Other platforms retain direct
process cancellation with the bounded pipe wait. A timeout is still `ERROR`,
never a valid empty scan.

### Development and holdout reporting

`datasets/split.v1.json` records the original 23 dev / 21 holdout pairs. Among executable
pairs, dev contains 14 in-scope cases and holdout contains 11 in-scope cases.
Keep that assignment stable when reporting experiments. Cases
`CVE-2016-6129`, `CVE-2020-16273`, and `CVE-2026-44362` from the original holdout
have already been used in debugging discussion; a later run over all 11 must
not be called an untouched blind test. Report tuning-exposed cases separately
and disclose model knowledge of public CVEs. A high score on these fixtures
alone does not establish discovery performance on unseen defects.

For repeatability, run separate `evaluate` invocations with `--samples 1` in the
scanner command and retain each result directory. Report the vulnerable/fixed
paired pass rate, specificity, invalid/incomplete counts, cost, and run-to-run
variation. Larger scanner `--samples` values measure expanded work within one
attempt. Cache speedups and improved recall require measurements; no multiplier
or target score is implied by the engineering changes.

For repeated full-repository scans, add scanner `--codeql-cache-dir <dir>` or set
`TEECHECK_CODEQL_CACHE_DIR` to reuse versioned source and CodeQL database masters.
Queries use private database copies; cache validation and copying still cost time
and disk. See [cache and resume details](../tee-usage-scanner/docs/HARNESS.md).
Scanner `--resume` continues an existing run with matching source and settings;
the runner's `evaluate` intentionally starts a fresh attempt. Do not inject resume
into the scanner command to reuse an old attempt, or count a resumed Planner as a
new independent sample.

### `reports/`

Small, reviewable benchmark result summaries. Reports identify the scanner
revision, model configuration without credentials, evaluated cases, metrics,
and limitations.

Raw run directories and model transcripts should remain outside Git. Reports
must never contain API keys.

## Quick Start

Run commands from the `teecheck-benchmark` project root. The scanner is a
separate sibling project at `../tee-usage-scanner`.

Validate all executable cases:

```sh
go run ./evaluator/runner -mode validate
```

Run TEECheck against all vulnerable/fixed pairs:

```sh
go run ./evaluator/runner \
  -mode evaluate \
  -results /tmp/teecheck-benchmark-results \
  -timeout 45m \
  -scanner-command '. ../tee-usage-scanner/.env.local; (cd ../tee-usage-scanner && go run ./cmd/teecheck run {input} --repo-url {repo_url} --commit {commit} --focus tee --run-id scan --output-dir {run_dir} --knowledge-root knowledge --max-cases 8 --max-hotspots 8)'
```

Command placeholders are shell-quoted by the runner:

| Placeholder | Value |
| --- | --- |
| `{input}` | Absolute path to the vulnerable or fixed fixture directory |
| `{run_dir}` | Fresh output directory owned by this attempt |
| `{case}`, `{variant}`, `{attempt_id}` | Case, source variant, and attempt identifiers |
| `{repo_url}` | Upstream repository from `case.yaml`; `{repository}` is a compatible alias |
| `{commit}` | Vulnerable revision from `case.yaml` or fixed revision from `oracle.yaml`; `{revision}` is a compatible alias |

Do not quote placeholders again. Unrelated shell syntax, including `${HOME}`
and braces in embedded scripts, remains intact.

For each scanner process the runner also sets `TEECHECK_REPO_URL` and
`TEECHECK_COMMIT` to that variant's upstream identity, replacing inherited values.
TEECheck uses these as defaults when `--repo-url` and `--commit` are absent, so a
command such as `teecheck run {input} --output-dir {run_dir}` also works for
cropped fixtures without their own Git metadata. Explicit scanner flags take
precedence. If a command sources another environment file, that file can replace
the defaults; the explicit flags in the example above preserve the case identity.
Every resulting bundle must still match the requested repository and revision;
missing or conflicting identity is rejected rather than scored. Supplying this
metadata does not turn a cropped fixture into a full Git checkout or create a
CodeQL database.

Rescore existing results:

```sh
go run ./evaluator/runner \
  -mode score \
  -results /tmp/teecheck-benchmark-results
```

The score is written as both `score.json` and `score.md` in the selected results
directory.

## Current Scope

- Stored public-CVE source pairs: 44; executable: 43 (25 in scope, 18 out)
- Executable source samples: 86; one additional pair requires source review
- Executable platforms: OP-TEE, Open Enclave, Trusted Firmware-M, and Occlum
  — all TEE-internal (trusted OS / secure world / enclave)

Two known limitations to keep in mind when reading results:

- Scans run against the pinned `scan_paths` (the files the upstream fix
  touched), so the executable track measures file-level detection, not
  whole-repository triage. It answers "given the right file, does the scanner
  recognise the weakness", not "can it find the needle in the repo".
- The corpus skews toward Arm TrustZone / OP-TEE platform-implementation bugs.
  Web3 / attestation-usage targets (the dcap-qvl / FPC style repositories the
  tool is aimed at) are not yet represented and should be added as non-CVE
  in-scope fixtures.
