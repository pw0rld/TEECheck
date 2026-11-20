# Planner and benchmark reliability hardening

Baseline: `16fa94e`. Scope: `tee-usage-scanner/`, `teecheck-benchmark/`, and
their canonical artifact schemas. Validation used Go 1.25.6 on macOS arm64,
Git history, `rg`, writable temporary caches, fake LLM clients, and in-memory
HTTP transports. Live model credentials were absent from the test environment.

## Changes

- Split planner token accounting into reconnaissance and investigation;
  reserve a finalization allowance inside the total budget. Check the next
  request before dispatch and bound output at the provider transport. Budget
  pressure, including a malformed-response retry, can enter finalization.
- Lower indexed reconnaissance to three modules, six functions across two
  modules. Allow source-observed leads without a CodeQL function card. Reject
  unobserved paths, invented observation references, and uncovered line ranges.
- Keep `obs:` observation identifiers separate from persisted ToolFact paths;
  retain a diagnostic when an identifier is used in the wrong field.
- Disable legacy pre-investigation architecture/invariant stages by default.
  `--enable-legacy-prior` opts in. Record the policy in the manifest and ignore
  stale prior artifacts when disabled. Old manifests without the new field
  retain their original review behavior.
- Mark empty symbol/function-card indexes as unavailable and persist partial
  coverage in the index, project map, and manifest.
- Visit all annotation candidates in module-interleaved batches, resolve each
  response against its displayed candidate set, and canonicalize merged facts.
  The annotator remains an explicit API, not an additional default model call.
- Preserve `related_twes` and validated source locations in final findings.
  Match benchmark targets by file, family, and known line location; a symbol
  cannot override a contradictory precise location. Report unrelated findings
  separately and expose an empty in-scope evaluation track.
- Review all 44 benchmark oracles. Correct two source pairs whose vulnerable
  and fixed variants were reversed, and quarantine one incomplete pair.
  See the benchmark's `reports/2026-11-21-oracle-review.md` for per-case evidence.
- Resolve source-search paths against the real repository boundary, reject
  escaping explicit paths, and skip external symlinks in recursive search.
- Merge duplicate subset CasePacks while preserving evidence and keeping
  different explicit symbols/security categories separate.
- Bound each Verifier case to four follow-up queries and 128 KiB of accumulated
  context. Exhaustion produces an inconclusive memo without another model call.
- Repair the `plan` alias and replace obsolete README instructions.

## Regression evidence

New tests first exposed the old behavior: unavailable symbol data advertised
as available; source-only leads refused; lost late-alphabet annotation targets;
ignored legacy-prior controls; missing finding-family metadata; file-only
benchmark matches; hidden incidental findings; out-of-root source reads; and
unbounded Verifier follow-ups. The resulting regressions pass.

Independent source review additionally found an old-manifest compatibility
case and phase-switch/finalization budget edge cases. Regressions now cover
those cases, partial provider usage, and all three provider output-limit
encodings. An end-to-end fake-client run proves that source reading can open a
lead, reach `llm_done`, and produce a valid run bundle without legacy priors or
CodeQL.

## Final validation

Both modules passed:

```sh
go test ./... -count=1
go vet ./...
```

Fresh builds of `cmd/teecheck` and `evaluator/runner` passed. The benchmark CLI
validator reports 43 passing source pairs and one explicit `REVIEW` case,
`CVE-2019-1010297`. Of the 43 executable pairs, 25 are in TWE scope and 18 are
out of scope. `git diff --check` passed.

Tests used temporary fixture/cache directories and no live API
credentials. Real-CodeQL integration tests were skipped because CodeQL was not
available on this machine. No live-model benchmark was rerun, so this change
does not claim a measured improvement in detection accuracy. The paired
annotation regression checks stable role identities across a representative
source fix; it does not promise identical answers from an arbitrary live model.
