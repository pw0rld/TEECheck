# TEECheck Event Schema

**Status**: v1, provisional. Schema-breaking changes require bumping
the version number in this file and a CHANGELOG entry.

This document is the authoritative reference for `events.jsonl` and
the content-addressed blob store written by every TEECheck run.
Stats, replay, review UI, and external dashboards all consume these
events — the schema is a contract.

## Why an event stream

TEECheck runs produce many artifacts (manifests, evidence bundles,
hypotheses, challenges, verifier memos, arbiter findings). These are
useful as final state snapshots but poor at answering questions like
"what did the planner *try* in round 3?", "which file did the
verifier actually read?", or "how much did this run cost?".

The event stream is the answer: an append-only sequence of typed
facts emitted by agents during a run. Downstream consumers fold over
the stream to derive metrics, reconstruct timelines, or replay
decisions. Events are facts, not transcripts — large bodies (prompts,
responses, tool args) live in a separate content-addressed blob store
referenced from the event.

## On-disk layout

```
runs/<run-id>/
├── 00_manifest.json
├── 01_profile/
├── 02_graph/
├── 03_cases/
├── 04_planner/
│   ├── rounds.jsonl              ← legacy planner debug log (kept)
│   └── evidence_bundle.json
├── 05_expert/
├── 06_challenger/
├── 06_verifier/
├── 07_arbiter/
├── events.jsonl                  ← **this document's subject**
└── blobs/
    └── <sha256>.txt              ← prompt / response / tool-args bodies
```

`events.jsonl` is at the run root, not under any stage subdirectory,
because events are intentionally cross-stage: a single timeline
spanning the planner, the four audit agents, the report generator,
and any tool calls in between.

## File format — JSONL

One JSON object per line, UTF-8, no trailing comma, newline-terminated.
Events are appended; the file is never rewritten. A single recorder
flushes after every event so `tail -f events.jsonl` works in real time.

The `seq` field is monotonically increasing within a single run. When
a run resumes (verifier or arbiter re-invoked against an existing
run dir), the recorder reads the existing file and continues numbering
from `max(seq)+1`. There are no gaps unless the file was manually
edited; malformed lines are skipped during recovery without resetting
the counter.

Time uses RFC 3339 nanosecond UTC. Sort by `seq`, not `time` — clock
adjustments can produce non-monotonic timestamps but `seq` is always
correct.

## Common fields (every event)

| field    | type   | required | notes                                                |
|----------|--------|----------|------------------------------------------------------|
| `seq`    | int64  | yes      | monotonic per recorder; starts at 1                  |
| `time`   | string | yes      | RFC 3339 nano UTC                                    |
| `type`   | string | yes      | discriminator; one of the types listed below         |
| `run_id` | string | yes      | run identifier from the manifest                     |
| `agent`  | string | no       | emitter id (`planner-001`, `expert-001`, …)          |
| `case_id`| string | no       | populated for case-scoped events                     |
| `round`  | int    | no       | populated for planner / round-scoped events          |

Every other field is type-specific and uses `omitempty` — fields
absent from a given event are simply not present in the JSON line.

## Event types

### `run_started`

Emitted once at the top of `pipeline.Run`, immediately after the run
directory and recorder are ready.

| field    | meaning                              |
|----------|--------------------------------------|
| `target` | input target (URL or local path)     |
| `mode`   | `llm` or `heuristic`                 |
| `focus`  | focus area (`tee`, `auth`, ...)      |

Example:
```json
{"seq":1,"time":"2026-04-25T09:23:01.123456Z","type":"run_started",
 "run_id":"oasis-core-l3","target":"/tmp/scans/oasis-core",
 "mode":"llm","focus":"tee"}
```

### `run_completed`

Emitted once at the end of `pipeline.Run` via deferred call. Always
fires, even on error.

| field    | meaning                                            |
|----------|----------------------------------------------------|
| `reason` | `completed` or `error`                             |
| `error`  | populated when `reason == "error"`                 |

### `planner_round_started` / `planner_round_completed`

Bracket each planner round.

`planner_round_started` carries `round` (1-indexed). No payload.

`planner_round_completed` carries `round`, `action_count` (actions the
planner actually executed in this round, after loop-detector
filtering), and `observation_count` (entries in the round's
observation list).

### `llm_call_started` / `llm_call_completed`

Bracket every call to the configured LLM client. Currently emitted by
the planner only; the four audit agents will be wired in subsequent
commits.

`llm_call_started` carries `agent`, `model`, `round`. No body.

`llm_call_completed` carries:

| field           | meaning                                                          |
|-----------------|------------------------------------------------------------------|
| `model`         | model name passed by caller (`glm-4.7`, etc.)                    |
| `tokens_in`     | provider-reported prompt tokens, or `chars/4` estimate fallback  |
| `tokens_out`    | same, for completion                                             |
| `prompt_blob`   | `sha256:<hex>` ref into `blobs/`                                 |
| `response_blob` | `sha256:<hex>` ref into `blobs/`                                 |
| `error`         | populated on call failure; tokens and blobs may be empty         |

Failed calls still emit `llm_call_completed` (with `error` populated)
so consumers can pair every `_started` with a `_completed`.

### `tool_call_started` / `tool_call_completed`

Bracket every tool invocation. Two emitter classes write these:

- the **planner** (in-process actions like `read_file`, `list_dir`,
  `tree_sitter_outline`, `done`) — emits the minimal field set
- the **executor** (subprocess tools routed through
  `internal/executor`, e.g. `ripgrep`, `semgrep`, `codeql`) — emits
  the minimal set plus a profile snapshot and execution facts

`tool_call_started`:

| field              | who emits  | meaning                                                          |
|--------------------|------------|------------------------------------------------------------------|
| `tool_name`        | both       | logical tool name                                                 |
| `tool_args_blob`   | both       | `sha256:<hex>` ref to args (one-per-line for executor argv)       |
| `network`          | executor   | `none` / `restricted` / `allow` — policy at invocation time       |
| `write`            | executor   | `none` / `run-dir-only` / `workspace`                             |
| `timeout_ms`       | executor   | resolved timeout (default 60000 if caller did not set Profile)    |
| `max_output_bytes` | executor   | resolved output cap (default 4 MiB)                               |

The four executor fields surface what *actually* ran, including the
defaults the executor filled in. Tool calls that did not go through
the executor leave them at zero/empty.

`tool_call_completed`:

| field              | who emits  | meaning                                                          |
|--------------------|------------|------------------------------------------------------------------|
| `tool_name`        | both       | logical tool name                                                 |
| `tool_ok`          | both       | true iff the call produced a usable result                        |
| `tool_duration_ms` | both       | wall clock                                                        |
| `tool_exit_code`   | executor   | process exit code (0 on success; non-zero is *not* a failure on its own) |
| `truncated`        | executor   | true if `max_output_bytes` was reached on stdout or stderr        |
| `error`            | both       | populated only on true execution failures (timeout, binary not found, etc.) |

**Error / ExitCode semantics.** A process that started and exited
cleanly leaves `error` empty even when its exit code is non-zero.
This matters for tools whose normal vocabulary includes non-zero
exits — `rg` returns 1 when nothing matched, `semgrep` returns
non-zero alongside valid JSON findings. Callers distinguish "tool
said no" from "execution broke" by checking `error`, then
`tool_exit_code`. `tool_ok` is the convenience boolean for the
"everything went fine" case.

Tool stdout and stderr are not blobbed in v1. They live in the
existing `04_planner/rounds.jsonl` observation records (truncated
to ~4000 chars). Future commits may move full outputs into blobs.

## Blob store

`blobs/<sha256-hex>.txt` is a flat directory of content-addressed
files. Identical content is stored once: `BlobStore.Write` is
idempotent. Filenames are always lowercase hex of the sha256 sum
of the body, with a `.txt` suffix (chosen for default text-mode
viewing convenience; bodies may contain any bytes).

Events reference blobs as `sha256:<hex>` strings (no `.txt` suffix in
the ref). To resolve:

```
ref      = "sha256:abc123..."
hex      = strings.TrimPrefix(ref, "sha256:")
filename = hex + ".txt"
path     = blobsDir + "/" + filename
```

Blob writes use `tmp + rename` so concurrent readers never see
truncated content.

## Citation contract (forthcoming, commit 5+)

The planned `claim_emitted` event type will introduce a typed citation
field:

```json
{
  "type": "claim_emitted",
  "agent": "expert",
  "case_id": "...",
  "claim_id": "...",
  "claim": "AVR signature is verified but enclave identity policy is missing",
  "cited_bytes": [
    {
      "file": "runtime/src/common/sgx/ias.rs",
      "start_line": 142,
      "end_line": 158,
      "start_byte": 4192,
      "end_byte": 4781,
      "sha256": "..."
    }
  ]
}
```

Claims without `cited_bytes` will be stripped before report
generation. Line range is for human review; byte range + sha256 is
for machine verification — line numbers shift under reformatting,
byte offsets and content hashes do not. See
`docs/ADVERSARIAL_INDEPENDENCE.md` for the rationale.

## Consumer guidance

Reading the stream:

```bash
# Quick filter
jq -c 'select(.type == "llm_call_completed")' events.jsonl

# Token total per agent
jq -r 'select(.type == "llm_call_completed")
       | "\(.agent)\t\(.tokens_in + .tokens_out)"' events.jsonl \
  | awk '{s[$1]+=$2} END{for (k in s) print k, s[k]}'

# Tool latency p95
jq -r 'select(.type == "tool_call_completed")
       | .tool_duration_ms' events.jsonl | sort -n | awk '
       {a[NR]=$1} END {print a[int(NR*0.95)]}'
```

Resolving blobs:

```bash
ref="sha256:abc123..."
cat "blobs/$(echo "$ref" | sed 's/^sha256://').txt"
```

## Compatibility & versioning

- Adding new optional fields to existing events is **backward
  compatible** and does not require a version bump.
- Adding new event types is **backward compatible**; consumers should
  ignore unknown `type` values.
- Removing or renaming fields, or changing field semantics, is
  **breaking**: bump the schema version at the top of this file and
  add a `schema_version` field to the affected events.

The first breaking change will introduce the version field uniformly;
until then, absence of `schema_version` implies v1.

## Stability guarantees

- `events.jsonl` is append-only for the duration of a run.
- Readers may safely tail the file with `tail -F`.
- Crash mid-write may leave a partial last line; consumers must skip
  any line that does not parse as JSON.
- Blob filenames never change once written.
- The blob directory is shared across resumed runs in the same run
  directory; this is intentional (content addressing makes collisions
  impossible by construction).
