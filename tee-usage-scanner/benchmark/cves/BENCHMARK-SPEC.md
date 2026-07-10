# TEE CVE Benchmark Specification

## Purpose

The 183 CVE records are a candidate corpus, not 183 executable tests. This
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

`case.yaml` pins the CVE, platform, repository, vulnerable revision, fixed
revision, build command, analysis command, and fixture hashes. `oracle.yaml`
records the expected verdict, TWE class, primary location, required evidence
path, and explicitly acceptable alternate locations.

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
5. The expected TWE class and evidence path are reviewed.
6. The case builds or validates in an isolated test command.

Every current documentation-only record remains `excluded` until a case
directory satisfies this gate.

## Metrics

Report source and policy suites separately. For each suite report precision,
recall, F1, evidence-path accuracy, TWE classification accuracy, and paired
regression accuracy. Knowledge-only records are reported as corpus coverage and
must never be included in the scoring denominator.

## Leakage Controls

- The oracle must not be injected into the scanner prompt.
- CVE identifiers and patch messages should be hidden in blind evaluation.
- Positive and negative fixtures must be near-identical except for the fix.
- Train/development and held-out projects must be separated by repository or
  vulnerability family, not merely by file.
- Tool crashes, build failures, and unsupported languages are reported
  separately from security verdicts.
