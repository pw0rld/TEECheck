# LLM-Driven Iterative Planner (Scanner Agent Rework)

**Status**: Draft — awaiting user review
**Date**: 2026-04-11
**Author**: Claude (with pw0rld)
**Supersedes**: Keyword-scoring hotspot selection in `internal/repomap/run.go` and `internal/hotspots/run.go`
**Chinese version**: `2026-04-11-llm-planner-design.zh-CN.md`

## 1. Motivation

The current Scanner agent picks hotspots by scoring files and symbols against
hand-written English keyword lists (`repomap/run.go:scoreValue` and
`classifyBoundary`). This has structural problems that cause real TEE bugs to
be silently filtered out before any LLM sees them:

1. Code that uses non-standard naming (`check`/`guard`/`ensure` instead of
   `verify`/`auth`) scores zero and drops out of the top-16 cutoff.
2. The hard cap of 16 important files / 16 important symbols has no module
   diversity — a single high-scoring area can consume all slots.
3. Scoring looks only at file paths and symbol names, never at file contents.
4. Graph connectivity is used as an importance proxy, but utility helpers
   (high in-degree, low security relevance) routinely outscore narrow sensitive
   entry points.
5. The boundary classifier (`classifyBoundary`) is a second keyword-based
   filter on top of the first — files that survive scoring can still be
   dropped if their path does not match one of 7 hard-coded kind keyword
   groups.
6. No feedback loop from `knowledge/learned/` back into scoring.

The desired model is: **let an LLM do shallow reconnaissance on the repository
structure, then iteratively decide which static analysis tools to invoke and
where, driving toward sink-rooted reverse traces rather than keyword-based
forward filtering.**

## 2. Goals and Non-Goals

### Goals

- Replace keyword-driven hotspot selection with an LLM-driven iterative
  planner (L3 from brainstorming).
- Introduce real call-site reverse tracing from a catalog of sinks (FFI,
  `unsafe`, attestation verify, crypto, state mutation, etc.) using
  tree-sitter as the v1 parsing engine.
- Preserve the existing `kind → obligations` case template mapping — expert,
  challenger, verifier, and arbiter agents remain unchanged.
- Keep heuristic mode (`--mode heuristic`) fully working as a fast, LLM-free
  path and as a fallback when the planner fails.
- Produce a complete audit trail of every planner round for reviewability.

### Non-Goals (v1)

- Multi-language support beyond Rust. Go/Solidity/Python/TypeScript are v2.
- LSP integration (rust-analyzer, gopls). Semantic call graphs beyond
  tree-sitter syntax are v2.
- Joern / CodeQL integration. Those stubs remain stubs.
- Automatic writeback of `proposed_sinks` into `knowledge/sinks/`. v1 records
  proposals only; curator review is manual until v2.
- Custom semgrep rule packs. v1 does not ship any.

## 3. Architectural Overview

### 3.1 New Pipeline Shape

```
repofetch → preprocessor(profile)
         → SCANNER AGENT (L3 Planner)
         │    seed state (profile + shallow tree)
         │         │
         │         ▼
         │    ┌── round N ──┐
         │    │ LLM thought │ ← working memory
         │    │ + actions   │ ← sink catalog
         │    └──┬──────────┘ ← observations so far
         │       │
         │       ▼
         │    action executor (sandboxed)
         │       │
         │       ▼
         │    observations → append to state
         │       │
         │       └── done? ── no → next round
         │                  └── yes
         │         │
         │         ▼
         │    evidence_bundle.json
         └───────┬──────────────────────
                 ▼
         cases → expert → challenger → verifier → arbiter
```

Scanner agent's job changes from "run graph + score" to "drive planner loop".
The old regex graph + keyword scoring is preserved as a single action
(`legacy_keyword_scan`) available in the planner's action menu; the LLM
decides whether to call it.

### 3.2 Planner State Machine

States: `SEEDED → PLANNING → EXECUTING → OBSERVING → (loop to PLANNING) → DONE`

Each round:

1. **PLANNING** — LLM sees `(working_memory, recent_observations,
   action_history, remaining_budget)` and outputs a structured response
   containing `thought` + a list of `actions` to execute.
2. **EXECUTING** — Actions run in order. Each has its own timeout and output
   size cap; failure is not fatal.
3. **OBSERVING** — Results are appended to state, over-sized outputs are
   truncated, and the candidate list is updated.
4. **Termination check** — `done` action, budget exhausted, loop detected, or
   repeated malformed output.

### 3.3 Context Window Management

`PlannerState` is structured, not an append-only transcript, to prevent
unbounded prompt growth:

```
PlannerState {
  profile: ProjectProfile
  tree_summary: string        // initial tree + size stats
  rounds: []RoundRecord       // full trace, persisted to disk
  candidates: []Candidate     // accumulated suspected regions
  sinks_seen: []SinkHit       // discovered sink locations
  budget_state: BudgetState   // remaining rounds/tokens/wall_clock
}
```

Each LLM prompt contains:

- A condensed profile (~300 tokens)
- The last 2 rounds' full observations (~5-10k tokens each)
- All accumulated candidates (~2k tokens)
- Remaining budget and a short system prompt (~1k tokens)

Full trace is persisted to `04_planner/rounds.jsonl` for auditability but is
**not** fed back into the LLM — that file is for humans and post-hoc analysis.

## 4. Action Menu (v1)

The planner exposes 9 actions. LLM responses are strict JSON and validated
against per-action schemas. Invalid actions return a validation error to the
LLM and do not consume a round.

| Action | Purpose | Implementation |
|---|---|---|
| `list_dir(path, depth)` | Inspect subtree structure | `os.ReadDir`, depth cap 3 |
| `read_file(path, start, end)` | Read a line range | Native Go, cap 500 lines |
| `ripgrep(pattern, globs)` | Fast text search | `exec` ripgrep, cap 200 match lines |
| `tree_sitter_outline(path)` | Extract functions / structs / impls | `go-tree-sitter` + Rust grammar |
| `reverse_trace(file, symbol, depth)` | BFS backward from a sink | tree-sitter call-site search, depth cap 3 |
| `legacy_keyword_scan()` | Run existing mapper + hotspots | Wraps current code, returns top-16 |
| `repomix_summarize(path)` | Subtree repomix digest | Wraps existing `internal/repomix` |
| `sink_catalog_lookup(category)` | Fetch a sink category definition | Reads `knowledge/sinks/rust.json` |
| `done(summary, candidates)` | Terminate and emit bundle | Final action |

Explicitly deferred to v2+: LSP (rust-analyzer), Joern, CodeQL, custom
semgrep rule packs, non-Rust tree-sitter grammars.

### 4.1 Action Executor Sandbox

All path-taking actions go through `planner/actions/sandbox.go`:

1. All path arguments are normalized via `filepath.Clean` + `filepath.IsLocal`.
2. Absolute resolved paths must satisfy `strings.HasPrefix(abs, repoRoot)`.
3. Symlinks are not followed (`os.Lstat`); any symlink is treated as out of
   bounds.
4. `exec`-based actions (ripgrep) pass all user input as separate argv
   elements — no shell concatenation.
5. Planner has no write actions — the filesystem view is read-only.

Sandbox violations are returned as action errors, never as panics.

## 5. Sink Catalog

### 5.1 Source of Truth

v1 ships hand-curated catalogs under `knowledge/sinks/`:

```
knowledge/sinks/
├── rust.json          ← v1 primary
├── go.json            ← v2
└── README.md          ← sink taxonomy
```

### 5.2 Schema (`rust.json`)

```json
{
  "schema_version": "teecheck.sink_catalog.v1",
  "language": "rust",
  "categories": [
    {
      "id": "ffi_extern",
      "description": "FFI boundary into C/assembly — arguments are untrusted",
      "match": {
        "kind": "syntax",
        "patterns": ["extern \"C\"", "#[no_mangle]"]
      },
      "severity_hint": "high"
    },
    {
      "id": "unsafe_block",
      "description": "Arbitrary unsafe — pointer ops, uninit memory, raw syscalls",
      "match": { "kind": "syntax", "patterns": ["unsafe {", "unsafe fn"] },
      "severity_hint": "medium"
    },
    {
      "id": "sgx_ecall",
      "description": "Intel SGX enclave entry/exit",
      "match": {
        "kind": "symbol",
        "symbols": ["sgx_tstd::*", "sgx_urts::*", "sgx_create_report", "sgx_verify_report"]
      },
      "severity_hint": "high"
    },
    {
      "id": "attestation_verify",
      "description": "Quote / report verification entry points",
      "match": {
        "kind": "symbol",
        "symbols": ["*::verify_quote*", "*::verify_report*", "*::verify_attestation*"]
      },
      "severity_hint": "high"
    },
    {
      "id": "crypto_sign_seal",
      "description": "Signing / sealing / key derivation",
      "match": { "kind": "symbol", "symbols": ["*::sign*", "*::seal*", "*::derive_key*"] },
      "severity_hint": "medium"
    },
    {
      "id": "state_mutation",
      "description": "On-chain state writes (runtime module storage)",
      "match": { "kind": "symbol", "symbols": ["Store::*::insert", "Store::*::set", "*::commit"] },
      "severity_hint": "medium"
    },
    {
      "id": "rofl_host_bridge",
      "description": "ROFL app <-> host socket / channel",
      "match": { "kind": "symbol", "symbols": ["appd::*", "*::socket*"] },
      "severity_hint": "high"
    }
  ]
}
```

Two matching modes:

- **`syntax`** — tree-sitter node text match (e.g. unsafe block detection)
- **`symbol`** — symbol name glob (e.g. `*::verify_quote*`)

### 5.3 LLM Interaction with the Catalog

The catalog is an audit checklist *for the LLM*, not an auto-executed rule
set. The LLM calls `sink_catalog_lookup(category_id)` or
`sink_catalog_lookup(*)`, sees the definitions, and decides which sinks to
reverse-trace via `reverse_trace(file, symbol, depth)`.

### 5.4 LLM-Proposed Sinks

`evidence_bundle.proposed_sinks[]` records categories the LLM invents during
a run. These are **not automatically written back** to `knowledge/sinks/` in
v1 — they are flagged for human curator review. The closed-loop writeback is
v2.

## 6. Artifact Schemas

### 6.1 Evidence Bundle

Final planner output, primary input to `cases` stage:

```json
{
  "schema_version": "teecheck.evidence_bundle.v1",
  "run_id": "2026-04-11-...",
  "repo": { "url": "...", "commit": "...", "focus": "tee" },

  "planner_meta": {
    "rounds_used": 6,
    "rounds_budget": 8,
    "tokens_used": 42000,
    "wall_clock_ms": 138000,
    "termination_reason": "llm_done | budget_exhausted | loop_detected | llm_malformed | planner_failed",
    "truncated": false
  },

  "candidates": [
    {
      "id": "candidate-001",
      "kind": "attestation",
      "priority": "high",
      "paths": ["runtime-sdk/src/modules/rofl/attestation.rs"],
      "symbols": ["verify_enclave_rak_pub"],
      "why_selected": [
        "sink:attestation_verify matched at runtime-sdk/src/modules/rofl/attestation.rs:142",
        "reverse_trace depth 2 from verify_enclave_rak_pub -> handle_register -> dispatch",
        "no caller-binding check between dispatch and verify"
      ],
      "evidence_refs": ["round-3.obs-2", "round-4.obs-1"],
      "sink_category": "attestation_verify",
      "confidence": 0.78
    }
  ],

  "sinks_observed": [
    {
      "category": "unsafe_block",
      "hits": [ { "path": "...", "line": 42, "snippet": "unsafe { ... }" } ]
    }
  ],

  "proposed_sinks": [
    {
      "category_id_suggested": "rofl_appd_message_decode",
      "rationale": "LLM observed that appd message decoding has trust implications not covered by existing catalog",
      "example_symbols": ["appd::decode_message"]
    }
  ],

  "errors": [ { "round": 2, "action": "tree_sitter_outline", "error": "..." } ],
  "final_summary": "..."
}
```

### 6.2 Rounds Log

`runs/<run-id>/04_planner/rounds.jsonl` — one JSON object per round with full
LLM thought + every action's full input/output (pre-truncation when possible).
Used for debugging and post-hoc analysis, never fed back to the LLM.

### 6.3 Hotspot Index Shim

v1 continues to write `runs/<run-id>/04_hotspots/hotspot_index.json` by
down-converting the evidence bundle's candidate list into the legacy schema.
This avoids breaking existing fixtures, tests, and any external consumer.
v2 can deprecate it.

### 6.4 Directory Layout

```
runs/<run-id>/
├── 00_manifest.json
├── 01_profile/project_profile.json
├── 02_graph/graph.json              # possibly empty (planner did not call legacy_keyword_scan)
├── 03_repo_map/repo_map.json        # same as above
├── 04_planner/                      # new
│   ├── rounds.jsonl                 # full audit trail
│   ├── evidence_bundle.json         # primary output
│   └── sink_hits.json               # human-readable sink hit summary
├── 04_hotspots/hotspot_index.json   # shim for v1 back-compat
├── 05_cases/case-NNN.json           # reads evidence_bundle
├── 04_expert/...
├── 05_challenger/...
├── 06_verifier/...
└── 07_arbiter/...
```

## 7. Pipeline Integration

### 7.1 Mode Dispatch

- `--mode heuristic` → Scanner agent runs old mapper+hotspots path unchanged.
  Planner is skipped entirely.
- `--mode llm` (existing) → Scanner agent invokes `planner.Run`, planner
  writes evidence bundle, cases stage reads bundle.

### 7.2 cases Stage Changes

`internal/cases/run.go`:

```go
func Run(cfg) error {
  // 1. If evidence_bundle.json exists, read candidates from it.
  // 2. Otherwise fall back to hotspot_index.json (heuristic mode).
  // 3. For each candidate call caseTemplate(kind) → obligations.
  // 4. Write case-NNN.json.
}
```

The `caseTemplate(kind)` mapping is not changed. Candidates carry the same
`kind` values that the classifier used to emit (`attestation`,
`authorization`, `state_machine`, `key_management`, `fallback`,
`ffi_boundary`, `host_interface`, `runtime_entry`), so expert / challenger /
verifier / arbiter require zero code changes.

### 7.3 Downstream Agents — No Changes

Expert, challenger, verifier, and arbiter agents operate on case packs. Case
packs keep their existing schema. The planner affects **which** regions get
case packs and **what evidence** is attached, but not the downstream pipeline.

## 8. Budget and Termination

### 8.1 Defaults

| Dimension | Default | CLI flag | Purpose |
|---|---|---|---|
| max rounds | 8 | `--planner-max-rounds` | Hard ceiling on planning loops |
| max LLM tokens | 120000 | `--planner-max-tokens` | Cost control (input + output tokens summed across all rounds) |
| per-action timeout | 30s | `--planner-action-timeout` | Single-tool runaway guard |
| total wall clock | 10min | `--planner-wall-clock` | End-to-end hard stop |

These tuples should also be settable per-provider in config (e.g. local GLM
defaults to unlimited tokens, Claude Opus defaults to rounds=6 / tokens=60k).

### 8.2 Automatic Termination Conditions

1. `done(...)` — LLM voluntarily terminates (normal path).
2. Any budget dimension exhausted — planner injects a "budget_exhausted"
   signal into the final round's prompt. If LLM still does not emit `done`,
   the executor synthesizes a `done` action using the current candidates.
3. **Loop detection** — the same action with the same arguments appearing 3
   times in a row is rejected; the LLM receives "you are repeating, try a
   different approach" as an observation.
4. Two consecutive rounds with no change to the `candidates` list → forced
   termination (the LLM is spinning).
5. Two consecutive malformed LLM outputs → degrade to `legacy_keyword_scan`,
   emit bundle with `termination_reason = "llm_malformed"` and
   `truncated = true`.

## 9. Error Handling

### 9.1 Hard Invariant

**The planner always produces an `evidence_bundle.json`, even on failure.**
Downstream cases / expert / challenger / verifier / arbiter either receive
real candidates or fall back to the heuristic path. Planner errors never
cause `teecheck run` to exit with an error by default.

Opt-in `--strict-planner` flag inverts this for CI use: planner failure → run
exits non-zero.

### 9.2 Action-Level Errors

Each action returns `ActionResult { ok: bool, output: string, error: string }`.
The LLM sees `error` as a string and can choose to fall back to a different
action.

- Tool missing (rg / tree-sitter binding) → `ok: false, error: "tool X not installed"`
- Timeout → `ok: false, error: "timeout after 30s"`, partial output preserved
- Output > 50KB → truncate to 50KB, keep head + tail, mark `truncated: true`
- Invalid path / out-of-bounds → validation fails, action not executed

### 9.3 LLM-Level Errors

- JSON parse failure → retry once with parse error in prompt
- Action schema validation failure → validation error returned to LLM, round
  not consumed
- LLM API timeout → round counted as failed, feeds loop detection
- 2 consecutive failures → degrade per 8.2 condition 5

### 9.4 Pipeline-Level Errors

- Catastrophic planner failure → empty evidence bundle with
  `termination_reason = "planner_failed"`, detailed error logged to stdout
  with a prominent warning:
  ```
  ⚠  Planner failed after N rounds (reason: ...). Falling back to heuristic hotspots.
      Full trace: runs/<run-id>/04_planner/rounds.jsonl
  ```
- Pipeline continues. cases stage reads the empty bundle, detects it, and
  reads `hotspot_index.json` shim if available.

## 10. Testing Strategy

### 10.1 Unit Tests

Each action has a companion `_test.go` using `testdata/` fixture repos:

- **Action correctness** — one fixture per action exercising happy path.
- **Sandbox** — a dedicated `TestActionExecutor_PathEscape` covering `../`,
  absolute paths, symlinks, and ~20 other malicious inputs.
- **Budget exhaustion** — mock LLM returning more actions indefinitely;
  assert correct termination for each of `max_rounds`, `max_tokens`,
  `wall_clock`.
- **Loop detection** — mock LLM repeating the same action; assert rejection
  on the third occurrence.
- **Malformed JSON** — mock LLM returns broken JSON; assert retry logic.
- **Sink catalog loader** — schema validation, rejection of malformed
  patterns.

### 10.2 Integration Tests (Mocked LLM)

`internal/planner/planner_integration_test.go`:

- A testdata Rust repo containing `unsafe`, `extern "C"`, and a synthetic
  attestation function.
- Mock LLM delivers a deterministic scripted sequence (round 1 `list_dir`,
  round 2 `sink_catalog_lookup`, round 3 `reverse_trace`, round 4 `done`).
- Assertions: the evidence bundle's candidates contain the expected paths and
  symbols, `rounds_used == 4`,
  `termination_reason == "llm_done"`.

### 10.3 Live LLM Smoke Test

`internal/planner/live_test.go`, gated on `TEECHECK_LIVE_LLM` env var:

- Runs on a small Rust repo (testdata or a single oasis-sdk crate).
- Uses the real configured provider (GLM / OpenAI / etc.).
- Assertions: non-empty candidates, rounds in [2, 8], wall clock < 5 min, at
  least one candidate's `sink_category` comes from `rust.json`.

### 10.4 What We Deliberately Do Not Test

- tree-sitter parse correctness (upstream responsibility).
- repomix (already has its own tests).
- Semantic LLM output quality (not a unit test concern).

## 11. Code Organization

```
internal/
├── planner/                       # new, core
│   ├── planner.go                 # Run(ctx, cfg) entry + main loop
│   ├── state.go                   # PlannerState + persistence
│   ├── prompt.go                  # system prompt + round prompt builders
│   ├── budget.go                  # BudgetState + termination checks
│   ├── loop_detect.go             # repetition / stall detection
│   ├── planner_test.go
│   ├── planner_integration_test.go
│   └── live_test.go
│
├── planner/actions/               # new, one file per action
│   ├── registry.go                # action name → handler + schema validation
│   ├── sandbox.go                 # path normalization, escape, symlink checks
│   ├── list_dir.go
│   ├── read_file.go
│   ├── ripgrep.go
│   ├── tree_sitter_outline.go
│   ├── reverse_trace.go
│   ├── legacy_keyword_scan.go     # wraps existing mapper + hotspots
│   ├── repomix_summarize.go       # wraps existing internal/repomix
│   ├── sink_catalog_lookup.go
│   ├── done.go
│   └── *_test.go
│
├── planner/sinks/                 # new
│   ├── loader.go                  # read knowledge/sinks/*.json
│   ├── matcher.go                 # syntax / symbol matching
│   └── loader_test.go
│
├── artifacts/types.go             # modified: add EvidenceBundle, Candidate, SinkHit
├── scanner/scan.go                # modified: llm mode delegates to planner.Run
├── cases/run.go                   # modified: prefer evidence_bundle, fall back to hotspot_index
├── config/config.go               # modified: new --planner-* flags and --strict-planner
└── runfs/paths.go                 # modified: new bundle / rounds log / sink hits paths

knowledge/
├── sinks/                         # new
│   ├── rust.json                  # v1 primary content
│   └── README.md
└── wiki/                          # unchanged
```

### Estimated Code Volume

- `internal/planner/*.go` — ~600 LOC
- `internal/planner/actions/*.go` — ~900 LOC (9 actions × ~100 LOC)
- `internal/planner/sinks/*.go` — ~300 LOC
- `knowledge/sinks/rust.json` — ~200 lines
- Edits to existing files — ~200 LOC
- Tests — ~1500 LOC
- **Total ~3700 LOC**

Estimated wall clock: 3–5 days (optimistic, tree-sitter Go binding smooth) to
1–2 weeks (pessimistic, cgo toolchain / grammar version issues).

## 12. Implementation Milestones

PR-sized, each independently reviewable and revertible:

### M1 — Artifact schema + sandbox + basic read actions

- `artifacts.EvidenceBundle`, `Candidate`, `SinkHit` types.
- `internal/planner/actions/sandbox.go` with full path escape test suite.
- `list_dir`, `read_file`, `ripgrep` actions with per-action unit tests.
- No planner loop yet — actions testable in isolation.

### M2 — Sink catalog + tree-sitter outline

- `knowledge/sinks/rust.json` seed content.
- `internal/planner/sinks/{loader,matcher}.go` + tests.
- `tree_sitter_outline` action using `go-tree-sitter` + Rust grammar.
- **Highest technical risk milestone** — cgo / grammar version issues
  surface here, worst case we revisit tooling choice before committing to M3.

### M3 — Planner main loop + remaining actions

- `internal/planner/{planner,state,prompt,budget,loop_detect}.go`.
- `reverse_trace`, `legacy_keyword_scan`, `repomix_summarize`,
  `sink_catalog_lookup`, `done` actions.
- `planner_integration_test.go` with mocked LLM passing end-to-end.

### M4 — Pipeline integration

- `scanner/scan.go`: `--mode llm` dispatches to `planner.Run`.
- `cases/run.go`: reads evidence bundle, falls back to hotspot index.
- `config/config.go`: `--planner-*` flags and `--strict-planner`.
- `runfs/paths.go`: new paths.
- Heuristic mode remains fully unchanged.

### M5 — Live smoke test + documentation

- `live_test.go` against oasis-sdk with real LLM provider.
- Update `README.md` with planner flags and behavior.
- Update `docs/MULTI_AGENT_HARNESS.md`.

(Prompt tuning is an ongoing activity beyond M5, not itself a milestone.)

## 13. Risks and Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| tree-sitter Go binding / cgo toolchain issues | Medium | M2 is isolated; failure there triggers a tooling revisit without touching M3+ |
| LLM prompt instability (round-over-round repetition, bad JSON) | High | Loop detection, malformed-output retries, forced degradation to `legacy_keyword_scan` |
| Cost overruns on large repos | Medium | Four-dimensional budget with hard walls, per-provider default tuning |
| Silent degradation (user thinks they ran llm mode, got heuristic) | Medium | Prominent stdout warning on fallback; `--strict-planner` opt-in for CI |
| Schema drift between evidence bundle and cases stage | Low | Keep `kind` values identical to legacy classifier output; shared constant set in `artifacts` |
| Sandbox escape through crafted paths | Low | Dedicated sandbox test suite, symlink rejection, argv-only exec |

## 14. Open Questions for Future Work (Not v1)

- Closed-loop `proposed_sinks` → `knowledge/sinks/` writeback by curator.
- LSP integration for semantic call graphs (rust-analyzer, gopls).
- Tree-sitter grammars for Go, Solidity, Python, TypeScript.
- Per-run learned adjustments (TP/FP history influences candidate ranking).
- Joern / CodeQL as heavyweight action options when available.

## 15. Success Criteria

v1 is considered successful when:

1. `teecheck run --mode llm <oasis-sdk>` produces an `evidence_bundle.json`
   with at least 5 high-quality candidates that a human auditor agrees are
   worth investigating.
2. At least 2 of those candidates are in files whose path / symbol names
   would not have scored highly under the keyword-based system (i.e.
   candidates the old system would have missed).
3. End-to-end run time is within 2x of the current heuristic mode.
4. No regression in `--mode heuristic` output on existing test fixtures.
5. The live smoke test passes reliably against GLM and one OpenAI-compatible
   provider.
