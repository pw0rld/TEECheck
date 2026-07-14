# TEECheck Benchmark

This directory contains the vulnerability corpus, executable source fixtures,
evaluation runner, and reviewable score reports used to measure TEECheck.

## Directory Layout

### `cases/`

Executable benchmark cases. Each case represents one vulnerability and contains
an exact vulnerable/fixed source pair:

```text
cases/CVE-YYYY-NNNN/
├── case.yaml          # Repository, revisions, scan paths, and file hashes
├── oracle.yaml        # Vulnerability location, trigger, and required evidence
├── vulnerable/        # Source before the security fix
├── fixed/             # Source after the security fix
├── patches/fix.patch  # Exact upstream security patch
├── UPSTREAM-LICENSE   # optional copy of the upstream license text
└── README.md
```

Only `fixture_ready` cases in this directory participate in executable scanner
evaluation. There are currently 50 executable cases, producing 100 scan
samples: 50 vulnerable and 50 fixed. Another 18 directories preserve
pending-source candidates but are excluded from scoring.

### `cves/`

The broader TEE CVE research corpus. It contains one Markdown record per CVE,
plus the complete catalog, collection methodology, benchmark specification, and
machine-readable manifest.

Most CVEs here are candidates rather than executable tests. A CVE enters
`cases/` only after its affected source, fixed source, patch, trigger, and oracle
can be reviewed and pinned.

Important files:

- `cves/CATALOG.md`: complete human-readable CVE index.
- `cves/MANIFEST.jsonl`: machine-readable status for every CVE.
- `cves/COLLECTION.md`: sources, search strategy, and known blind spots.
- `cves/BENCHMARK-SPEC.md`: fixture admission and scoring requirements.
- `cves/_TEMPLATE.md`: template for new CVE records.

### `runner/`

The Go evaluator used to validate fixtures, invoke a scanner, read TEECheck
`findings.json`, compare findings with each case oracle, and calculate metrics.

Supported modes:

- `validate`: verify case metadata, source hashes, patches, and oracle structure.
- `evaluate`: scan every vulnerable/fixed pair and then score the results.
- `score`: score previously generated scanner results without rerunning scans.

The evaluator reports TP, FP, FN, TN, precision, recall, F1, specificity, and
paired pass rate. A case passes only when the vulnerable side is detected and
the fixed side is not reported as the same vulnerability.

### `reports/`

Small, reviewable benchmark result summaries. Reports identify the scanner
revision, model configuration without credentials, evaluated cases, metrics,
and limitations.

Raw run directories and model transcripts should remain outside Git. Reports
must never contain API keys.

## Quick Start

Run commands from the `tee-usage-scanner` module root.

Validate all executable cases:

```sh
go run ./benchmark/runner -mode validate
```

Run TEECheck against all vulnerable/fixed pairs:

```sh
go run ./benchmark/runner \
  -mode evaluate \
  -results /tmp/teecheck-benchmark-results \
  -timeout 45m \
  -scanner-command '. ./.env.local; go run ./cmd/teecheck run {input} --mode llm --focus tee --run-id scan --output-dir {run_dir} --knowledge-root knowledge --max-cases 8 --max-hotspots 8'
```

Rescore existing results:

```sh
go run ./benchmark/runner \
  -mode score \
  -results /tmp/teecheck-benchmark-results
```

The score is written as both `score.json` and `score.md` in the selected results
directory.

## Current Scope

- CVE research records: 186
- Executable vulnerability cases: 50
- Source samples: 100
- Executable platforms: OP-TEE, Open Enclave, Trusted Firmware-M, Linux KVM
  SEV/SEV-SNP, Linux TDX/confidential-VM support, Occlum, and `sgx_tstd`

The CVE corpus measures collection coverage. The executable cases measure
scanner accuracy. These numbers must not be combined into a single benchmark
score.
