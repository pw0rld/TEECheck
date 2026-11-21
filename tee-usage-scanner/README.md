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

For a local fixture, set `TEECHECK_REPO_URL` and `TEECHECK_COMMIT` to identify the
upstream source revision. `--repo-url` and `--commit` override these environment
defaults; otherwise repository identity is detected from the input. The
benchmark runner supplies both variables separately for each case variant.

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

The project map also exposes a neutral entry-surface index. Its signals are
global non-static definitions, function references in global initializers,
pointer/integral parameter combinations, and definitions with no recorded
direct in-tree caller. These are navigation clues, not proof of external
reachability, attacker-controlled input, or a vulnerability. The repository
card previews a few definitions; `list_entry_surfaces` pages through the rest
with optional module and signal filters. Source locations and evidence are
kept in `repo_facts.v1.json` and `project_map.v1.json`.

For a normal zero-lead completion, available entry candidates require reading
the opening source windows of `min(3, entry count)` different definitions,
across `min(2, module count)` modules. Each window covers the first 12 lines
or the whole definition when shorter. Only complete source lines actually
sent to the model count: cards, outlines, duplicate reads, requested ranges,
and undisplayed blobs do not. Opening a supported audit lead remains separate
from this completion gate. Budget exhaustion still permits exit but records
unmet coverage; it does not turn an incomplete zero-lead result into safety.

Default budgets distinguish reconnaissance, investigation, and finalization:
100,000 reconnaissance tokens, 140,000 investigation tokens, a 240,000 aggregate
ceiling, and a 20,000-token finalization reserve within that ceiling. The
planner also limits rounds and elapsed time. `--samples N` repeats planner
passes with an avoid-list, then reviews the merged candidates once.
It measures additional exploration coverage. Use separate complete runs with
`--samples 1` to measure repeatability.

The wall-clock allowance stays at 10 minutes per planner pass by default.
Use `--planner-wall-clock 30m` explicitly for deeper runs; the same allowance
is recorded in the manifest. Compare the entry-index change under the same
budget first, then measure extended-budget runs separately.

The coverage ledger and report record entry windows and module spread per
sample. Offline validation marks a zero-lead run with missing entry coverage
or a degraded entry index as incomplete coverage, rather than a clean result.

During reconnaissance or investigation, `trace_taint` can inspect parameter-to-sink flow using a
fixed C/C++ CodeQL template and the run's existing database. It requires an
observed source or sink definition from that planner pass, without requiring
an existing lead. Its facts can supply the evidence for `open_audit_lead`.
`source_path`
disambiguates same-named source definitions; omitted `source_param_index`
means all parameters. Sources include parameter values and one-level pointer
contents. This does not model every alias or indirection.

The action accepts identifier-only function names, supported sink kinds and
at most eight barrier functions, never QL code. `sink_func` refines a call sink;
use `array_index` or `pointer_deref` without `sink_func` for expression sinks.
Barrier functions only filter call-result nodes: they do not prove that the
program checked a return value or enforced a guard.

`--max-taint-queries` defaults to 8 uncached attempts per planner pass; `0`
removes that separate cap. `--taint-query-timeout` defaults to `5m` and is
bounded by the remaining planner wall clock. Matching queries reuse a
run-local, content-checked artifact without spending another attempt. The
cache assumes the pinned source tree remains unchanged during a run.

`TEECHECK_CODEQL_ANALYZE_THREADS` overrides the general
`TEECHECK_CODEQL_THREADS` only for analysis. For example, set the general value
to `1` for database creation and the analysis value to `2` for query evaluation.
An explicit nonzero `AnalyzeOptions.Threads` takes precedence; an analysis
value of `0` falls back to the general setting. More query threads can increase
memory use, so compare stability and timings on the target environment.

Every CodeQL-emitted path witness is retained in a scope- and hash-bound
`02_tool_facts/trustir/taint-*.json` ToolFact. The 32 KiB observation returns up
to five witnesses by default (maximum ten), ordered by the length of the
returned witnesses; displayed hops default to twelve (maximum twenty).
Counts are not exhaustive path enumeration or a global shortest-path claim.
Missing locations and display truncation are explicitly recorded. Zero paths,
failed analysis and paths removed by barriers never imply safety.

Use `update_lead.add_taint_fact_refs` with the returned `fact_ref` to preserve
the trace. `formalize_contract` automatically carries the lead's validated
trace references forward; Expert, Challenger and Verifier receive the same
bounded immutable evidence and independently check the relevant source.

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

HTTP 429 and rate-limit responses use the bounded retry policy. Other HTTP 4xx
responses remain terminal. CodeQL database creation retries a recognized JVM
memory/native-runtime crash once with a single thread; ordinary compiler
crashes do not qualify for that added native-crash retry.

Explicit upstream policy refusals are non-retryable, including refusals returned
with HTTP 5xx status codes. The planner records `policy_refusal`, retains opened
audit leads, and writes the unreviewed scope to its round log and evidence bundle.
The run stops without automatically altering the rejected request or sending it
to another review role. Provider response details remain available for diagnosis.

## Case contracts and verification

Pass B can call `formalize_contract` during investigation, emit
`done.case_invariants`, or attach `case_invariants` to an investigation.
Every Planner contract must refer to an AuditLead from the same
sample. The scanner binds its subjects to current source definitions and saves
line ranges, content hashes, the logical property and a separate verification
plan. Contracts are also available to findings produced by the deterministic
lane. Unsupported properties remain explicit; a missing query does not prove
safety or a violation.

The compact final-round prompt retains this contract format and the current
sample's lead IDs. If `done` still returns legacy candidates, the planner makes
at most one closing request within the same round, token budget, and deadline
(at most 8,192 output tokens). It supplies successful source reads and matching
leads from that sample, then binds accepted contracts directly to the original
candidate's CasePack. Missing leads, unread or unknown symbols, invalid replies,
and insufficient budget leave explicit gaps and an unformalized candidate.
An upstream policy refusal stops this request without a prompt or model retry.

The lead controls support an incremental workflow:

- `update_lead` keeps cited notes and ruled-out hypotheses across rounds. Each
  note is limited to 240 UTF-8 bytes and must cite this sample's successful
  observation or an actually executed, validated ToolFact. Notes remain agent
  interpretations. The active-lead prompt uses at most 2 KiB per lead and
  8 KiB overall, explicitly marking omitted records.
- `formalize_contract` immediately checks source subjects, evidence references,
  scope and registered query parameters. Invalid drafts return a correctable
  action error without advancing the lead. Accepted contracts persist through
  an empty final candidate list or a later model failure.
- `close_lead` archives a question with its reason and current-sample evidence.
  It does not assert safety or remove accepted contracts. Lead revisions are
  appended to `audit_leads.jsonl`; the last revision for each lead is current.

Cross-process resume still requires separate source-freshness validation.
The taint action supplies review evidence; it does not add an automatic
`satisfied` or `violated` contract query.

Expert and Challenger independently review each contract. Verifier produces one
`InvariantAssessment` per contract, separating `satisfied`, `violated`, and
`unresolved` from the original obligation. Typed contract arbitration applies
mechanical gates to those assessments without another free-form LLM verdict:

- `confirmed_candidate` requires a validated violation and a complete,
  independently corroborated chain of evidence.
- `likely_issue` requires either a validated local violation with independent
  support, or an explicitly unimplemented verification query with independently
  corroborated source witnesses and no outstanding counter-evidence.
- Tool errors, unproved preconditions, conflicting evidence, and unformalized
  new candidates remain `needs_review`.

A validated registered query retains its local `satisfied` or `violated`
assessment even when a model cannot establish cross-function preconditions.
Those gaps remain in `missing_evidence` and prevent promotion to a positive
security finding. A source-only review that contradicts the proposed issue is
recorded as `unresolved / source_contradicted`; it does not manufacture a
deterministic proof of a fix. Runtime arbitration and offline validation use
the same independent-review gates.

The first registered contract query is
`cpp.contract.direct_struct_field_assignment`. It checks only whether one exact
function definition contains a direct `Assignment` AST node to a named field of
a named struct. Initializers, helper calls, indirect writes and overloaded
assignment operators do not satisfy that syntactic property; compound assignment
nodes do. The contract kind is `direct_struct_field_assignment`, with
destination `Struct.field`, one target field, and query parameters `type` and
`field`. With multiple subjects, `subject="path::symbol"` explicitly selects
the query target; other subjects supply consumer/caller context. Stronger
value-propagation, authority, dominance or all-path
properties cannot be verified by substituting this query.

Recheck a frozen logical contract against a separate local checkout:

```bash
go run ./cmd/teecheck verify-contract \
  --contract /path/to/original-contract.json \
  --repo-root /path/to/fixed-checkout --commit FIXED_REVISION \
  --output-dir /path/to/contract-rechecks
```

This strips the old source anchors, witnesses and lead before binding the new
revision. Results go to a fresh `verify-*` directory and never feed the knowledge
store or autonomous discovery. Git checkouts must match the requested revision
and have no tracked modifications. Non-Git fixtures are labeled `local_partial`.
Without a successful registered CodeQL query, the result remains `unresolved`.
A successful query can retain its local result without a Verifier model, but
the unproved preconditions and missing source review remain explicit. The
command does not convert unavailable verification into success. A quiet
independent scan of a fixed version is distinct from a `satisfied` contract recheck.

CodeQL resource defaults can be set with `TEECHECK_CODEQL_RAM` (MiB) and
`TEECHECK_CODEQL_THREADS`. Explicit nonzero options override those defaults;
zero leaves the CLI defaults unchanged when the environment is unset. A known
internal JVM/TRAP database-build failure gets one clean retry with one thread;
ordinary build failures and cancellation do not retry.

## Commands and controls

| Command | Purpose |
| --- | --- |
| `run TARGET` / `plan TARGET` | Full audit pipeline |
| `report --run-dir DIR` | Render complete findings, packets, and coverage |
| `validate-run --run-dir DIR` | Offline artifact/sequence/hash/schema validation |
| `verify-contract --contract FILE --repo-root DIR --commit REV` | Isolated logical-contract recheck |
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
| `--samples N` | Planner passes with an avoid-list; default 1 |
| `--output-dir DIR`, `--run-id ID` | Choose artifact destination and identity |
| `--knowledge-root DIR` | Select the knowledge tree |
| `--enable-legacy-prior` | Opt into old pre-investigation model stages |
| `--llm-provider glm\|openai\|deepseek` | Select provider preset |
| `--llm-base-url`, `--llm-model` | Select endpoint/model |
| `--llm-transport chat_completions\|responses` | OpenAI transport |
| `--llm-reasoning-effort` | Reasoning effort for Responses |
| `--llm-max-tokens` | Per-call output-token limit |
| `--role-config FILE` | Startup model profiles per role; see [configuration](docs/ROLE_MODELS.md) |

Credentials and provider settings also accept `TEECHECK_LLM_*` environment
variables. `--max-hotspots` survives in the parser for old scripts but no longer
selects audit targets.

The `deepseek` preset defaults to `https://api.deepseek.com/v1`, Chat Completions,
and `deepseek-flash`. The [current official API documentation](https://api-docs.deepseek.com/api/create-chat-completion/)
lists `deepseek-flash` and `deepseek-v4-pro`; explicit model names are sent
unchanged so a compatible gateway can still serve older models.

For legacy `deepseek-chat`, an unspecified completion budget defaults to 8,192
tokens. An explicit CLI, environment, role profile, or programmatic budget is
preserved (programmatic callers can mark a default-sized override with
`LLMMaxTokensExplicit`). This is a compatibility default, not a claim that all current
DeepSeek models have an 8,192-token maximum. `deepseek-reasoner` omits temperature;
current DeepSeek thinking models also omit it unless thinking is disabled with
`--llm-reasoning-effort none`. See the [thinking-mode parameter rules](https://api-docs.deepseek.com/guides/thinking_mode/).

## Run artifacts

```text
runs/<run-id>/
  00_manifest.json
  01_context/                       # repo facts, project map, TWE context
  02_tool_facts/                    # persisted deterministic evidence
  03_cases/
  04_planner/                       # rounds, leads, coverage, contracts, evidence bundle
  04_expert/
  05_challenger/
  06_verifier/                      # per-contract assessments and registered query records
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
Each evaluation attempt has a fresh directory, an exit record and a repeated
`validate-run` gate. Invalid runs are `ERROR`; empty results with incomplete
reconnaissance/index coverage are `INCOMPLETE_COVERAGE`, not true negatives.
Reports distinguish Planner, deterministic and combined finding origins.

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
