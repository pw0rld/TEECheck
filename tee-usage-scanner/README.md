# TEECheck

TEECheck is a source-grounded TEE security research CLI. It combines a program
index, an LLM investigation planner, structured tool evidence, and four review
roles. Its findings are candidates for human review.

## Quick start

Requirements: Go 1.25+, Git, and `rg`. CodeQL is optional and must be installed
separately; the current program index uses its C/C++ extractor. Without a usable
index, the planner uses source-file reconnaissance and records partial coverage.

```bash
cd tee-usage-scanner
go build -o teecheck ./cmd/teecheck

# Configure credentials in the environment rather than command history.
export TEECHECK_LLM_API_KEY="your-key"

# GLM preset (Anthropic-compatible endpoint).
./teecheck run /path/to/project --llm-provider glm --llm-model glm-4.7

# OpenAI-compatible endpoint, including native Responses transport.
./teecheck run /path/to/project \
  --llm-provider openai --llm-base-url https://your-endpoint/v1 \
  --llm-model your-model --llm-transport responses \
  --llm-reasoning-effort high
```

A Git URL may replace the local path. `teecheck plan` is an alias for `run`.
All audit runs use the LLM pipeline; the old heuristic scanner was retired.

## Pipeline

```text
source acquisition and common revision/root
  -> preprocess
  -> program index (CodeQL when available)
  -> project map (repository, module, and function cards)
  -> optional legacy architecture/invariant stages
  -> deterministic supported fact queries
  -> planner reconnaissance -> source-grounded investigation
  -> merge and enrich CasePacks
  -> Expert -> Challenger -> Verifier -> Arbiter
  -> findings.json and review packets
```

The legacy pre-investigation architecture and invariant stages are disabled by
default. `--enable-legacy-prior` opts back into them for comparison with older
runs. Their absence is supported by downstream review and run validation.

The planner first reads the project's own structure and source. It must ground
an audit lead in observations from that pass. Without function cards it can use
observed file/symbol targets instead. After opening a lead, it can consult TWE
investigation methods and security obligations. Observing a file or receiving an
empty query result does not establish whole-repository safety.

Default budgets distinguish reconnaissance, investigation, and finalization:
60,000 reconnaissance tokens, 140,000 investigation tokens, a 200,000 aggregate
ceiling, and a 20,000-token finalization reserve within that ceiling. The
planner also limits rounds and elapsed time. `--samples N` repeats planner
passes with an avoid-list, then reviews the merged candidates once.

`tree_sitter_outline` is a compatibility action name: its implementation now
uses text heuristics. Parsed program relationships come from CodeQL. The index
explicitly reports unavailable/partial capabilities, including an empty symbol
or function-card result.

## Evidence and knowledge

Three kinds of information stay separate:

- Tool facts record observed source and query results, with scope and provenance.
- Agent assessments are revisable hypotheses and interpretations.
- Human review records determine confirmed outcomes and reusable feedback.

`knowledge/twe/definitions/` contains the TWE taxonomy and definitions.
`knowledge/twe/exemplars/` contains six detailed investigation methods covering
State, Flow, Guard, and Leakage. `knowledge/wiki/` holds curated obligations and
patterns; `knowledge/learned/` stores feedback. Lookup uses lightweight keyword
matching.

The current automatic fact lane is deliberately narrow: its supported operation
checks rollback-version propagation, and its shipped role table is for OP-TEE.
An LLM role-table annotator exists but is not automatically enabled. It visits
all enumerated function candidates in bounded, module-interleaved batches;
it no longer discards every name after the first alphabetical page.

The Challenger records an independent assessment before comparing it with the
Expert. The Verifier checks source citations and uses bounded follow-up dialogs.
The Arbiter gates confirmed wording on evidence completeness. None of these
mechanisms substitutes for a human verdict or an executable reproduction.

Explicit upstream policy refusals are non-retryable, including refusals returned
with HTTP 5xx status codes. The planner records `policy_refusal`, retains opened
audit leads, and writes the unreviewed scope to its round log and evidence bundle.
The run stops without automatically altering the rejected request or sending it
to another review role. Provider response details remain available for diagnosis.

## Commands and controls

| Command | Purpose |
| --- | --- |
| `run TARGET` / `plan TARGET` | Full audit pipeline |
| `report --run-dir DIR` | Render complete findings, packets, and coverage |
| `validate-run --run-dir DIR` | Offline artifact/sequence/hash/schema validation |
| `stats DIR` | Recorded run metrics |
| `review --run-dir DIR` | Record human judgments |
| `curator --run-dir DIR` | Curate feedback into the knowledge layer |
| `knowledge-init` | Initialize the knowledge layout |

Individual `preprocess`, `cases`, `expert`, `challenge`, `verifier`, and `arbiter`
commands remain available for stage-level work.

Common run controls:

| Flag | Purpose |
| --- | --- |
| `--hint TEXT` | Prioritize a concern without changing source scope |
| `--max-cases N` | Bound the number of reviewed case packs |
| `--samples N` | Independent planner passes; default 1 |
| `--output-dir DIR`, `--run-id ID` | Choose artifact destination and identity |
| `--knowledge-root DIR` | Select the knowledge tree |
| `--enable-legacy-prior` | Opt into old pre-investigation model stages |
| `--llm-provider glm\|openai` | Select provider protocol |
| `--llm-base-url`, `--llm-model` | Select endpoint/model |
| `--llm-transport chat_completions\|responses` | OpenAI transport |
| `--llm-reasoning-effort` | Reasoning effort for Responses |
| `--llm-max-tokens` | Per-call output-token limit |

Credentials and provider settings also accept `TEECHECK_LLM_*` environment
variables. `--max-hotspots` survives in the parser for old scripts but no longer
selects audit targets.

## Run artifacts

```text
runs/<run-id>/
  00_manifest.json
  01_profile/project_profile.json
  01_context/                       # repo facts, project map, TWE context
  02_tool_facts/                    # persisted deterministic evidence
  03_cases/
  04_planner/                       # rounds, leads, coverage, evidence bundle
  04_expert/
  05_challenger/
  06_verifier/
  07_arbiter/findings.json
  07_arbiter/packets/
  08_report/REPORT.md                # separate report command
  08_review/                        # optional human review
  09_curator/                       # optional feedback processing
  events.jsonl
  blobs/
```

`report` deterministically renders every validated finding and full review
packet. An optional LLM narrative is labeled non-authoritative; model failure
cannot remove findings or prevent the factual report from being written.

## Evaluation and development

`../teecheck-benchmark/` is a separate Go module with vulnerable/fixed source
pairs and a deterministic evaluator. It matches target location and TWE
metadata, reports incidental findings separately, and exposes an empty
in-scope track instead of presenting it as a valid capability metric.

`cmd/twescan` is a separate experimental, LLM-assisted query-generation entry
point; it is not the full audit pipeline and its supported families are limited.

```bash
# Unit tests use fake models. Clear live-provider credentials if you do not
# intend to run the opt-in live connectivity tests.
go test ./... -count=1 -skip '^TestLive'
go vet ./...

cd ../teecheck-benchmark
go test ./... -count=1
go vet ./...
```

See [the target architecture](docs/ARCHITECTURE.md) for the migration toward
case-scoped invariants and evidence-derived security architecture. That document
contains planned components as well as implemented ones. Historical evaluation
records describe their own revisions and must not be reused as current scores.
