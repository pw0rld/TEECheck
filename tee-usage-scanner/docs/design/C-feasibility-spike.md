# C/C++ Feasibility Spike — Result: PASS

**Date:** 2026-07-15
**Question:** Can the deterministic TWE path reach the C CVE cases (≈90% of the
benchmark), and can it judge a real one correctly? The Rust spine was proven
earlier (`M2-codeql-spike.md`); the corpus is mostly C.

**Answer:** Yes. CVE-2016-6129 (libtomcrypt RSA signature length) judges
correctly — vulnerable flagged, fixed clean, no false positive when scoped.

## The hard part, measured

CodeQL's C extractor + gcc are present (bundle `cpp-all`/`cpp-queries`). The
open risk was the database build: real CVE fixtures are single files that
`#include` project headers not shipped with the fixture, and the projects
(OP-TEE, TF-M, kernel) have heavy build systems.

Findings:

| Approach | Functions extracted | Verdict |
|---|---|---|
| single fixture file, `--build-mode=none` | **0** (file present, no AST) | header-less C does not parse |
| single file + partial stub header | **0** | stubs never complete enough for real code |
| **full cloned repo @ revision, `--build-mode=none`** | **780** (7769 calls) | works — headers present, no compile needed |

The decisive result: cloning the case's real repository at its pinned revision
and extracting the whole tree with `--build-mode=none` yields a fully queryable
AST — `rsa_verify_hash_ex` with all its calls (`der_decode_sequence_ex`,
`pkcs_1_v1_5_decode`, `memcmp`, …). **No cross-compile toolchain, no project
build system** — just `git clone @revision` + extract. `case.yaml` already
carries `repository` + `vulnerable_revision` + `fixed_revision`.

## Historical experiment: CVE-2016-6129

This experiment is retained as historical benchmark documentation only. The
custom C Guard TWE and its generated query were removed from the active TWE
catalog; CVE-2016-6129 is no longer mapped to a TWE.

The fix adds a `der_length_sequence` call computing the ASN.1 length and gates
acceptance (`*stat = 1`) on `reallen == outlen`. The vulnerable revision accepts
without it. The former custom C Guard query was:
the acceptance-bearing function does not call `der_length_sequence`.

Both databases were built by overlaying each fixture variant's
`rsa_verify_hash.c` onto the cloned tree (the tree supplies the headers). Result:

| Variant | scoped to the located file | Verdict |
|---|---|---|
| vulnerable | 1 result — `rsa_verify_hash_ex` | correct (flag) |
| fixed | 0 results | correct (quiet) |

Unscoped, the query also flags other verifiers that set `*stat=1` without the
check (`dsa_verify_key`, `ecc_verify_hash`, …) — expected breadth, removed by
scoping to the site the expert/TrustIR located (the pipeline pins by file+line).

## What C support needs (most of the pipeline is language-neutral)

Reused unchanged: TWE catalog (M1), TrustIR contracts, twexpert/GLM (reads C),
solver (M5), twescan orchestration, benchmark harness.

New, C-specific:

1. **DB build (M2-C)** — clone `repository`@`revision`, extract full tree with
   `--build-mode=none`. Proven here. Needs DB caching + disk (libtomcrypt 38 MB;
   the kernel cases are GBs and will be slow).
2. **Query generation (M4-C)** — C/C++ QL templates per family (`import cpp`;
   `Function`, `FunctionCall`, `Assignment`, `VariableAccess` instead of the
   Rust classes). One per family; the Rust queries do not transfer.
3. **Language dispatch** — twescan/twepipeline pick extractor + generator by the
   case's language.

## Caveats

- `--build-mode=none` skips real compilation, so macro/`#ifdef` configuration
  uses source defaults. Config-gated weaknesses (e.g. TF-M profile macros) may
  need a real build for fidelity.
- Kernel-scale trees are expensive to clone and extract; caching is required
  before running many cases.

## Decision

C is viable and the build risk is retired. Next: wire a C language path
(M2-C build + one C query generator) and score CVE-2016-6129 through the full
pipeline, then scale to more families.
