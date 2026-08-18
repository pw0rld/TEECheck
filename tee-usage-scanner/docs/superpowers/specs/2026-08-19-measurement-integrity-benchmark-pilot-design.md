# Measurement Integrity and Benchmark Pilot Design

## Status

Approved in the 2026-08-19 working session. Implementation may proceed without
another approval gate.

## Goal

Make TEECheck benchmark results structurally trustworthy before expanding the
evaluation corpus, then run a small diverse pilot that identifies generalized
pipeline failure classes without encoding benchmark answers into the scanner.

## Decision

Use a staged hybrid approach:

1. Fix defects that invalidate measurement, reproducibility, or artifact
   interpretation.
2. Run a six-pair pilot from `teecheck-benchmark` with one fixed model/config.
3. Classify misses by pipeline stage and fix generalized mechanisms only.
4. Defer broad prompt tuning and new target-specific fact fixtures until the
   pilot provides cross-case evidence.

## Measurement-Integrity Gate

The pilot may start only when:

- empty findings serialize as `[]`;
- findings and their closed enums validate before persistence;
- a run validator checks terminal status, stage artifacts, schemas, blob
  references, and blob hashes;
- manifests identify the actual scanner build, Go runtime, CodeQL version, LLM
  model/provider/transport, and resolved non-secret settings;
- planner budgets and termination metadata are internally consistent;
- truncation, query failures, and coverage gaps remain visible in final output;
- OpenAI Responses transport is native and regression-tested;
- subprocess timeout kills descendants promptly;
- the ordinary unit suite does not depend on an implicit network download.

## Architecture

### Artifact Contract

`internal/artifacts` owns stable wire types and closed-value validation.
`internal/schema` owns JSON schemas. A new `internal/runvalidate` package reads a
run directory without invoking LLMs or tools and returns structured validation
issues. The CLI exposes it as `teecheck validate-run --run-dir ...`.

### LLM Transport

The existing `llm.Client` remains unchanged. `internal/llm` gains a Responses
client selected by an explicit transport setting. It maps TEECheck messages to
Responses input messages and preserves wire request/response plus usage. Chat
Completions remains supported for existing providers.

### Reporting

Report facts, finding inventory, provenance, coverage, errors, and truncation
disclosures are assembled deterministically. An LLM may generate narrative, but
the final assembler verifies that every finding ID is represented and appends
the deterministic sections regardless of model output.

### Runtime Reliability

Planner metadata distinguishes per-pass and aggregate budgets. Coverage
failures are data, not log-only observations. Unix execution uses process-group
cancellation. Repomix unit tests use a fake executor; live download behavior is
an explicit integration test.

## Pilot Protocol

Select six vulnerable/fixed pairs using the checked-in split metadata:

- two near the currently supported property family;
- two C/C++ cases from different families;
- two cases from another language or project.

Use one sample, identical model configuration, and no target-specific hint.
Record detector source, top-location match, vulnerable/fixed discrimination,
planner termination, coverage, truncation, model usage, wall time, artifact
validation, and report completeness. Do not author new facts or exemplars from
holdout oracles.

## Failure Taxonomy

- `acquisition`: wrong revision or scope;
- `representation`: required source relationship absent from intermediate data;
- `discovery`: planner never reaches the relevant subsystem;
- `routing`: evidence exists but no case is created;
- `verification`: evidence window cannot resolve required links;
- `arbitration`: evidence is present but verdict is invalid or unstable;
- `reporting`: internal result is omitted, truncated, or misrepresented.

## Stop Conditions

Stop the pilot and return to repairs when a run cannot be validated, credentials
or provider availability block execution, or two cases expose the same
measurement-integrity defect. Scanner-quality misses remain pilot data and do
not stop the batch unless they make later results uninterpretable.

