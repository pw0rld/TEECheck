# TEE CVE Benchmark Specification

## Purpose

The 186 CVE records are a candidate corpus, not 186 executable tests. This
specification defines when a record becomes a benchmark case and prevents
hardware advisories, proprietary firmware issues, and source-level defects from
being scored as though they were equivalent.

## Required Case Layout

An executable case should eventually live under `benchmark/cases/<case-id>/`:

```text
case.yaml
README.md
vulnerable/
fixed/
oracle.yaml
```

`case.yaml` pins the CVE, platform, repository, vulnerable/fixed revisions,
authoritative source record, scan paths, and fixture hashes. The benchmark
runner supplies the scanner command and performs isolated fixture validation.
`oracle.yaml` records the expected verdict, primary vulnerability location,
required evidence path, and explicitly acceptable alternate locations.

## Case Classes

### Source Fixture

Use when vulnerable and patched source are public. The positive fixture contains
the real defect or a reviewable minimal reduction. The negative fixture contains
the corresponding fix. Static tools and the LLM are evaluated against the same
pair.

### Policy Fixture

Use for silicon, microcode, firmware, and TCB advisories that source scanning
cannot detect directly. The positive fixture is relying-party code that accepts
unsafe attestation status, missing SVN/advisory checks, debug state, or stale
TCB. The negative fixture enforces the required appraisal policy.

### Knowledge Only

Use when no public source, stable behavioral oracle, or meaningful policy
fixture exists. These records may inform prompts and threat models but contribute
neither true positives nor false negatives to benchmark scores.

## Scoring Gate

A case is `eligible` only if all of the following are true:

1. An authoritative advisory has been checked.
2. Affected and fixed revisions or policy semantics are pinned.
3. Positive and negative fixtures are present and deterministic.
4. The oracle was written from advisory/patch evidence, not scanner output.
5. The expected vulnerability location and evidence path are reviewed.
6. The case builds or validates in an isolated test command.

The executable runner additionally enforces an explicit `fixture_ready` status,
a resolvable `source_record`, scan paths that cover the oracle primary file, and
a non-empty patch that references at least one declared fixture file. Pending
candidates must be explicitly marked `pending_source` and are never included in
scoring.

Every current documentation-only record remains `excluded` until a case
directory satisfies this gate.

## Metrics

Report source and policy suites separately. For each suite report precision,
recall, F1, evidence-path accuracy, and paired regression accuracy.
Knowledge-only records are reported as corpus coverage and
must never be included in the scoring denominator.

For source-pair cases, the unit of evaluation is the pair. The vulnerable side
is a positive sample and the fixed side is its negative control. A pair passes
only when the scanner finds oracle-matching evidence in the vulnerable tree and
does not repeat that verdict in the fixed tree. Matching requires the oracle's
primary file plus the vulnerable function name or at least one reviewed semantic
term; arbitrary findings in the same file are not counted.

Scanner execution failures and timeouts stop evaluation and are not silently
converted into false negatives. This keeps availability failures separate from
security accuracy.

## Leakage Controls

- The oracle must not be injected into the scanner prompt.
- CVE identifiers and patch messages should be hidden in blind evaluation.
- Positive and negative fixtures must be near-identical except for the fix.
- Train/development and held-out projects must be separated by repository or
  vulnerability family, not merely by file.
- Tool crashes, build failures, and unsupported languages are reported
  separately from security verdicts.
