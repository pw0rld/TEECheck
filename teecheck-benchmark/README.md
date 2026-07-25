# TEECheck Benchmark

This directory contains the executable source fixtures, evaluation runner, and
reviewable score reports used to measure TEECheck.

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

Only `fixture_ready` cases in this directory participate in executable scanner
evaluation. There are currently 44 executable cases, producing 88 scan
samples: 44 vulnerable and 44 fixed. Every case has a checked-in vulnerable and
fixed source tree.

Every case is source-backed: it pins a public CVE (`detection_surface:
source`) with a real upstream repository, revisions, and record. Hand-authored
synthetic fixtures are not admitted — the benchmark measures detection of real,
public vulnerabilities.

Every executable case is a defect **inside the TEE** — the trusted OS, secure
world, enclave, or trusted application. A 2026-07 review removed seven cases
whose code lives in the untrusted host or normal world (Linux KVM/SEV
hypervisor, the Linux OP-TEE kernel driver, swiotlb DMA, a device-tree config,
and guest-kernel EFI): TEE-adjacent, but not a weakness in a TEE.

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

`primary_function` and `match_terms` are retained as human-review evidence only.
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

Current split of the 44 executable cases: 32 in scope, 12 out. In-scope
families: Flow 14, Leakage 9, State 5, Guard 4, Binding 0, Config 0, Design 0.
Oracle-location provenance: 30 single-file-fix, 12 multi-file-confirmed, 2
multi-file-corrected. Every case is leakage-suspect (all pin a public CVE).
Binding, Config, and Design have no cases yet and are the priority for new
cases, since Binding (subject binding) and Config (simulated / debug
attestation) are exactly the usage weaknesses most common in real audits. New
cases must be source-backed — a public CVE with a real vulnerable/fixed commit
pair, ideally from a Rust attestation repository such as dcap-qvl or an FPC
audit finding.

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
tags each finding with in its id (`TWE-<FAMILY>-NNN:...`), the analogue of a CWE
id. Class agreement, not free-text keyword overlap, is what counts; earlier
`match_terms` string matching both inflated true positives (an unrelated finding
that merely mentioned the file) and missed correct prose that used different
words. `match_terms` and `primary_function` are retained in the oracle as
human-review evidence only; they no longer gate scoring. Out-of-scope cases
(empty `twe_family`) have no expected class and are matched on file alone, on
their separate secondary track. Line-level agreement (the Juliet refinement) is
enforced **only when an oracle pins `primary_line`**: the scanner now emits a
structured `locations` array, and the finding must carry a location on the
primary file within a small tolerance. Oracles without `primary_line` are scored
on file + family alone, so lines can be added case-by-case to tighten scoring
without changing any case that has none. No oracle pins a line yet; populating
`primary_line` from each fix hunk is the next per-case step.

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
  -scanner-command '. ../tee-usage-scanner/.env.local; (cd ../tee-usage-scanner && go run ./cmd/teecheck run {input} --repo-url {repository} --commit {revision} --mode llm --focus tee --run-id scan --output-dir {run_dir} --knowledge-root knowledge --max-cases 8 --max-hotspots 8)'
```

Rescore existing results:

```sh
go run ./evaluator/runner \
  -mode score \
  -results /tmp/teecheck-benchmark-results
```

The score is written as both `score.json` and `score.md` in the selected results
directory.

## Current Scope

- Executable vulnerability cases: 44 (32 in TWE scope, 12 out; all public CVEs)
- Source samples: 88
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
