# Benchmark Language Inventory

Generated from the files under `benchmark/cases/*/vulnerable/` and the
`status` and `language` fields in each `case.yaml`. Candidate records without
source fixtures are listed separately under `benchmark/candidates/`.

## Summary

| Dimension | Count |
| --- | ---: |
| Total benchmark cases | 44 |
| `fixture_ready` cases | 44 |
| Cases containing C source or C headers | 40 |
| Rust cases | 3 |
| OCaml cases | 1 |
| Header/build-metadata-only case | 1 |

Language counts are non-exclusive. `CVE-2019-0876` contains both C and OCaml;
the OCaml file is Open Enclave's `oeedger8r` generator. The Rust cases are
`CVE-2021-44421`, `TWE-BIND-0001`, and `TWE-CONFIG-0001`.

`CVE-2017-1000412` is a special case: its fixture currently contains a C
header and a Makefile fragment, but no `.c` source file. It is counted as a
header/build-metadata case and should not be presented as a normal C semantic
fixture without further source enrichment.

## Candidate records without source fixtures

The 18 pending CVE records are not benchmark cases and are intentionally not
included in the per-case inventory below. They remain available under
`benchmark/candidates/source-pending/` for future source collection.

## Per-case inventory

| Case | Status | Language / artifact type | Evidence |
| --- | --- | --- | --- |
| CVE-2016-6129 | fixture_ready | C | `.c` |
| CVE-2017-1000412 | fixture_ready | C header + Makefile metadata | `.h`, `.mk`; no `.c` |
| CVE-2017-1000413 | fixture_ready | C | `.c` |
| CVE-2019-0876 | fixture_ready | C + OCaml | `.c`, `.h`, `.ml` |
| CVE-2019-1010292 | fixture_ready | C | `.c` |
| CVE-2019-1010293 | fixture_ready | C | `.c` |
| CVE-2019-1010294 | fixture_ready | C | `.c` |
| CVE-2019-1010295 | fixture_ready | C | `.c` |
| CVE-2019-1010296 | fixture_ready | C | `.c` |
| CVE-2019-1010297 | fixture_ready | C | `.c` |
| CVE-2019-1010298 | fixture_ready | C | `.c` |
| CVE-2019-25052 | fixture_ready | C | `.c` |
| CVE-2020-15107 | fixture_ready | C | `.c`, `.h`, assembly/config support files |
| CVE-2020-15224 | fixture_ready | C | `.c`, `.h`, `.edl` |
| CVE-2020-16273 | fixture_ready | C | `.c` |
| CVE-2021-27562 | fixture_ready | C | `.c` |
| CVE-2021-32032 | fixture_ready | C | `.c` |
| CVE-2021-40327 | fixture_ready | C | `.c`, `.h`, CMake metadata |
| CVE-2021-43619 | fixture_ready | C | `.c` |
| CVE-2021-44421 | fixture_ready | Rust | `.rs` |
| CVE-2022-46152 | fixture_ready | C | `.c` |
| CVE-2023-37479 | fixture_ready | C | `.c`, headers, assembly support files |
| CVE-2023-40271 | fixture_ready | C | `.c` |
| CVE-2023-41325 | fixture_ready | C | `.c`, `.h` |
| CVE-2023-51712 | fixture_ready | C | `.c` |
| CVE-2024-25742 | fixture_ready | C | `.c` |
| CVE-2024-45746 | fixture_ready | C | `.c` |
| CVE-2025-46733 | fixture_ready | C | `.c`, `.h` |
| CVE-2025-53022 | fixture_ready | C | `.c` |
| CVE-2026-33317 | fixture_ready | C | `.c` |
| CVE-2026-33662 | fixture_ready | C | `.c` |
| CVE-2026-40257 | fixture_ready | C | `.c` |
| CVE-2026-40290 | fixture_ready | C | `.c`, `.h` |
| CVE-2026-41434 | fixture_ready | C | `.c`, `.h` |
| CVE-2026-41514 | fixture_ready | C | `.c` |
| CVE-2026-41515 | fixture_ready | C | `.c` |
| CVE-2026-41516 | fixture_ready | C | `.c` |
| CVE-2026-42546 | fixture_ready | C | `.c` |
| CVE-2026-44362 | fixture_ready | C | `.c` |
| CVE-2026-45614 | fixture_ready | C | `.c`, `.h`, Makefile metadata |
| CVE-2026-45702 | fixture_ready | C | `.c`, `.h` |
| CVE-2026-53763 | fixture_ready | C | `.c`, `.h` |
| TWE-BIND-0001 | fixture_ready | Rust | `.rs` |
| TWE-CONFIG-0001 | fixture_ready | Rust | `.rs` |

## Interpretation for benchmark coverage

The executable corpus is heavily C-oriented: it primarily evaluates source
analysis on OP-TEE, Trusted Firmware-M, TF-M, and related C-based TEE code.
Rust coverage is currently limited to one CVE fixture and two TWE fixtures.
OCaml coverage is limited to one Open Enclave generator file. The pending
cases have no source tree and therefore cannot contribute to language-specific
scanner recall until their vulnerable and fixed revisions are materialized.
