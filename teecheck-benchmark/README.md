# TEECheck Benchmark

This directory contains the vulnerability corpus, executable source fixtures,
evaluation runner, and reviewable score reports used to measure TEECheck.

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
evaluation. There are currently 46 executable cases (44 public CVEs plus 2
synthetic), producing 92 scan samples: 46 vulnerable and 46 fixed. Every case
has a checked-in vulnerable and fixed source tree.

Every executable case is a defect **inside the TEE** — the trusted OS, secure
world, enclave, or trusted application. A 2026-07 review removed seven cases
whose code lives in the untrusted host or normal world (Linux KVM/SEV
hypervisor, the Linux OP-TEE kernel driver, swiotlb DMA, a device-tree config,
and guest-kernel EFI): TEE-adjacent, but not a weakness in a TEE. See
`knowledge/cves/TEE-STANDARD-REVIEW.md`.

Most executable cases pin a public CVE (`detection_surface: source`). A few are
**synthetic** (`detection_surface: synthetic`, id prefix `TWE-<FAMILY>-NNNN`):
hand-authored vulnerable/fixed pairs that do not track a CVE, used to cover TWE
families the CVE corpus misses. Synthetic cases skip the upstream provenance
checks (no repository revision or CVE record) but are held to every other
requirement — fixture hashes, vulnerable != fixed, a fix patch, and a complete
reviewed oracle.

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
  # synthetic             hand-authored pair, no CVE provenance
oracle_review.patch_files # how many files the fix patch touches (ripple indicator)
leakage_suspect           # true for public CVEs plausibly in the GLM training corpus;
                          #   false only for the synthetic (non-public) pairs
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

Current split of the 46 executable cases: 34 in scope, 12 out. In-scope
families: Flow 14, Leakage 9, State 5, Guard 4, Binding 1, Config 1, Design 0.
Oracle-location provenance: 30 single-file-fix, 12 multi-file-confirmed, 2
multi-file-corrected, 2 synthetic. Leakage-suspect (public CVE): 44; clean
(synthetic): 2.
Binding and Config are seeded by synthetic fixtures only and remain the
priority for new cases, since they are exactly the usage weaknesses (subject
binding, simulated / debug attestation) most common in real audits. Add more by
copying `TWE-BIND-0001` / `TWE-CONFIG-0001` and adapting the vulnerable/fixed
pair — ideally lifted from a real repository such as dcap-qvl or an FPC audit
finding.

### `knowledge/cves/`

The broader TEE CVE research corpus. It contains one Markdown record per CVE,
plus the complete catalog, collection methodology, benchmark specification, and
machine-readable manifest.

The CVE records here provide background material for evaluation and research.
Only cases with checked-in source pairs under `datasets/` are executable tests.

Important files:

- `knowledge/cves/CATALOG.md`: complete human-readable CVE index.
- `knowledge/cves/MANIFEST.jsonl`: machine-readable status for every CVE.
- `knowledge/cves/COLLECTION.md`: sources, search strategy, and known blind spots.
- `knowledge/cves/BENCHMARK-SPEC.md`: fixture admission and scoring requirements.
- `knowledge/cves/_TEMPLATE.md`: template for new CVE records.

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
  -scanner-command '. ../tee-usage-scanner/.env.local; (cd ../tee-usage-scanner && go run ./cmd/teecheck run {input} --mode llm --focus tee --run-id scan --output-dir {run_dir} --knowledge-root knowledge --max-cases 8 --max-hotspots 8)'
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

- CVE research records: 178
- Executable vulnerability cases: 46 (34 in TWE scope, 12 out; 44 public CVEs, 2 synthetic)
- Source samples: 92
- Executable platforms: OP-TEE, Open Enclave, Trusted Firmware-M, and Occlum
  — all TEE-internal (trusted OS / secure world / enclave)

The CVE corpus measures collection coverage. The executable cases measure
scanner accuracy. These numbers must not be combined into a single benchmark
score.

Two known limitations to keep in mind when reading results:

- Scans run against the pinned `scan_paths` (the files the upstream fix
  touched), so the executable track measures file-level detection, not
  whole-repository triage. It answers "given the right file, does the scanner
  recognise the weakness", not "can it find the needle in the repo".
- The corpus skews toward Arm TrustZone / OP-TEE platform-implementation bugs.
  Web3 / attestation-usage targets (the dcap-qvl / FPC style repositories the
  tool is aimed at) are not yet represented and should be added as non-CVE
  in-scope fixtures.
