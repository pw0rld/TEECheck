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
| `sink_catalog_lookup(scope)` | Fetch catalog headers, a full group, or a single category. `scope` is `"*"` / `"<group_id>"` / `"<group_id>.<category_id>"` | Reads `knowledge/sinks/rust.json` |
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

v1 scope is deliberately narrow: **attestation and key lifecycle only**.
Memory safety, host leakage, panic/debug smells, and generic runtime state
mutation are explicitly out of scope for this catalog. The LLM can still use
`ripgrep` or `read_file` to investigate anything outside the catalog; the
catalog just focuses the reverse-trace effort.

Categories are organized into **groups** so the LLM can fetch a table of
contents first and then drill down. Three groups in v1: `attestation`,
`tee_platform_syscalls`, `key_lifecycle`. Thirteen categories total.

```json
{
  "schema_version": "teecheck.sink_catalog.v2",
  "language": "rust",
  "groups": [
    {
      "id": "attestation",
      "description": "Report/quote generation, verification, identity/TCB checks, and freshness — the full remote-attestation chain",
      "categories": [
        {
          "id": "attestation_report_creation",
          "description": "Quote/report generation and report_data field binding. Audit: what data (session pk, nonce, challenge) is bound into the report.",
          "match": {
            "kind": "symbol",
            "symbols": ["sgx_create_report", "sgx_quote_*", "sgx_qe_*", "*::create_report*", "*::generate_quote*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_verification_and_trust",
          "description": "Verification entry points and the trust decisions made after verification. The exact trust-decision site is project-specific and must be located by reverse_trace from the verify call.",
          "match": {
            "kind": "symbol",
            "symbols": ["*::verify_quote*", "*::verify_report*", "*::verify_attestation*", "*::verify_evidence*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_identity_and_tcb_checks",
          "description": "MRENCLAVE/MRSIGNER equality checks and TCB/QEIdentity/collateral/CRL validation. Audit: comparison targets correct, expiration/revocation honored.",
          "match": {
            "kind": "symbol",
            "symbols": ["*MRENCLAVE*", "*MRSIGNER*", "*::check_tcb*", "*::verify_tcb*", "*::qe_identity*", "*::collateral*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "attestation_freshness",
          "description": "Nonce binding, challenge-response flow, time-window checks. Audit: replay resistance.",
          "match": {
            "kind": "symbol",
            "symbols": ["*::nonce*", "*::challenge*", "*::freshness*"]
          },
          "severity_hint": "high"
        }
      ]
    },
    {
      "id": "tee_platform_syscalls",
      "description": "Enclave entry/exit and SGX platform services — trust boundary crossings",
      "categories": [
        {
          "id": "sgx_ecall",
          "description": "Enclave entry — arguments are untrusted host input.",
          "match": { "kind": "symbol", "symbols": ["sgx_tstd::*", "sgx_urts::*", "#[ecall]"] },
          "severity_hint": "high"
        },
        {
          "id": "sgx_ocall",
          "description": "Out-of-enclave calls — return values are host-controlled and must be re-validated inside the enclave.",
          "match": { "kind": "symbol", "symbols": ["*::ocall_*", "sgx_ocall_*"] },
          "severity_hint": "high"
        },
        {
          "id": "sgx_platform_services",
          "description": "SGX platform services including QE, RA, and AESM interaction. Audit: error and degradation paths.",
          "match": { "kind": "symbol", "symbols": ["sgx_qe_*", "sgx_ra_*", "aesm_*", "*::aesm*"] },
          "severity_hint": "medium"
        }
      ]
    },
    {
      "id": "key_lifecycle",
      "description": "Key generation, derivation, sealing, signature ops, AEAD, and secret hygiene — complete key lifecycle audit",
      "categories": [
        {
          "id": "key_generation",
          "description": "Key pair / secret key generation and the RNG source used. In a TEE the RNG must be attested (OsRng/getrandom with platform hardware entropy), never thread_rng or seeded PRNGs.",
          "match": {
            "kind": "symbol",
            "symbols": ["KeyPair::generate", "*::SecretKey::random", "*::generate_keypair*", "OsRng", "thread_rng", "getrandom::*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "key_derivation_and_exchange",
          "description": "HKDF, KDF, derive_key, ECDH, X25519, key_agreement. Audit: context/info/salt binding prevents cross-context collision; peer identity is bound to an attested key.",
          "match": {
            "kind": "symbol",
            "symbols": ["*::derive_key*", "*::hkdf*", "*::kdf*", "*::key_agreement*", "*::diffie_hellman*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "key_sealing",
          "description": "SGX sealing, runtime sealing, and unsealing. Audit: sealing policy binds to MRENCLAVE vs MRSIGNER appropriately; unseal results are re-validated.",
          "match": { "kind": "symbol", "symbols": ["sgx_seal_data", "sgx_unseal_data", "*::seal*", "*::unseal*"] },
          "severity_hint": "high"
        },
        {
          "id": "signature_ops",
          "description": "Signing and signature verification. Audit: signing key source is attested/sealed; verification failure paths cannot fall through; verifying key is trusted.",
          "match": {
            "kind": "symbol",
            "symbols": ["*::sign", "*::sign_message*", "*::verify_signature*", "ed25519::*", "k256::*", "secp256k1::*"]
          },
          "severity_hint": "high"
        },
        {
          "id": "aead_encryption",
          "description": "AEAD seal/open (ChaCha20-Poly1305, AES-GCM, etc.). Audit: nonce uniqueness, key lifetime, associated data binding.",
          "match": {
            "kind": "symbol",
            "symbols": ["*::seal_in_place*", "*::open_in_place*", "chacha20poly1305::*", "aes_gcm::*"]
          },
          "severity_hint": "medium"
        },
        {
          "id": "secret_hygiene",
          "description": "Zeroize traits, secret wrapper types, and absence thereof. Audit: secret types lack Zeroize/ZeroizeOnDrop, or expose themselves via Debug/Display/serde.",
          "match": {
            "kind": "syntax",
            "patterns": ["Zeroize", "ZeroizeOnDrop", "Secret<", "secrecy::", "#[derive(Debug)]"]
          },
          "severity_hint": "medium"
        }
      ]
    }
  ]
}
```

Two matching modes:

- **`syntax`** — tree-sitter node text match (e.g. `Zeroize` presence)
- **`symbol`** — symbol name glob (e.g. `*::verify_quote*`)

Several category match patterns are intentionally loose (e.g. `attestation_verification_and_trust`). Precise location of
trust-decision sites and callers is left to the LLM via `reverse_trace`, not baked into the catalog.

### 5.3 LLM Interaction with the Catalog

The catalog is an audit checklist *for the LLM*, not an auto-executed rule set. `sink_catalog_lookup` supports three scope levels:

- `sink_catalog_lookup("*")` — returns group ids + descriptions only (~300 tokens). LLM's first call to see the table of contents.
- `sink_catalog_lookup("attestation")` — returns a full group with all its categories (~1.5k tokens). Used once the LLM decides a group is relevant.
- `sink_catalog_lookup("attestation.quote_verification")` — returns a single category definition (~300 tokens). Used for targeted drill-down.

Typical LLM flow: call `*` once → pick one or two groups → call the group(s) → pick categories to reverse-trace → call `reverse_trace(file, symbol, depth)` against the matched symbols to locate real trust-decision sites.

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
| L3 architectural bet does not pan out (LLM spins, low-quality candidates) | Medium | M5 live test is the verification gate. If it fails, fall back to the **hybrid Plan B** described in section 16.5: pre-stage runs sink catalog + tree-sitter outline deterministically to produce candidate seeds, agentic stage only does reverse_trace and verification on the seeds. |

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

## 16. Implementation Status (as of 2026-04-15)

This section tracks what is shipped vs deferred, so this spec stays a single
source of truth instead of drifting from the code.

### Shipped (v1)

| Spec section | Status | Code |
|---|---|---|
| §3 Architectural overview (planner → cases → 4-agent) | ✅ | `internal/pipeline/run.go` |
| §4 Action menu (9 actions: list_dir, read_file, ripgrep, tree_sitter_outline, reverse_trace, sink_catalog_lookup, legacy_keyword_scan, repomix_summarize, done) | ✅ | `internal/planner/actions/*.go` |
| §5 Sink catalog v2 (3 groups: attestation, tee_platform_syscalls, key_lifecycle) | ✅ | `knowledge/sinks/rust.json`, `internal/planner/sinks/` |
| §6 Artifact schemas (EvidenceBundle, Candidate, SinkHit, RoundRecord) | ✅ | `internal/artifacts/types.go` |
| §7 Pipeline integration (`run --mode llm`, `plan` shorthand) | ✅ | `internal/pipeline/run.go`, `cmd/teecheck/main.go` |
| §8 Four-dimensional budget (rounds / tokens / wall-clock / per-action timeout) | ✅ | `internal/planner/budget.go` |
| §9 Loop + stall detection, malformed JSON tolerance, retry on transient errors | ✅ | `internal/planner/loop_detect.go`, `internal/llm/retry.go`, `internal/llm/json.go` |
| Observed-paths hallucination defense (soft mid-rounds, hard final round) | ✅ | `internal/planner/planner.go` |
| §10 Test strategy (mocked-LLM integration tests, sandbox suite) | ✅ | `internal/planner/planner_test.go`, `internal/planner/actions/*_test.go` |
| §12 M1–M4 milestones | ✅ | tagged commits |

### Partial / Deferred

| Item | Status | Notes |
|---|---|---|
| §7.5 Hybrid Plan B fallback (planner failure → heuristic) | ❌ Missing | Planner errors currently abort the run; fallback to heuristic mode is not wired |
| §14 `proposed_sinks` writeback to `knowledge/sinks/` | ❌ Missing | `ProposedSinks` is captured in the bundle but no curator review/writeback loop exists |
| §14 Wiki obligations injection into planner prompt | ❌ Missing | `internal/planner/prompt.go` does not currently load `knowledge/wiki/obligations/*.md` |
| §14 Per-run learned priors (TP/FP history influences ranking) | ❌ Missing | No `learned/` reader on the planner side |
| §14 LSP integration (rust-analyzer / gopls) | ⏸ v2 | Explicitly deferred |
| §14 Tree-sitter grammars beyond Rust (Go / Solidity / Python / TS) | ⏸ v2 | Only Rust grammar is wired |
| §14 Joern / CodeQL heavyweight actions | ⏸ v2 | Stubs exist in `internal/staticcheck/` but no planner action |
| §15 Live smoke test passing on two providers | ⚠ Partial | Validated on GLM (`glm-4.7` via z.ai); OpenAI provider not yet validated |

### Validation Highlights

- **mobilecoin v13–v17 dogfood runs** consistently route the planner into
  `attest/`, `sgx/`, `enclave-boundary/`, `fog/*/enclave/`, and
  `consensus/enclave/` — directories the old keyword scorer could not reach.
  See `examples/mobilecoin-l3-v14-scan/REPORT.md`.
- **v17** was the first run where the LLM autonomously called `reverse_trace`
  and walked from `verify_report` back through `attest/ake/src/initiator.rs`
  and `attest/ake/src/responder.rs`, producing a real consistency finding
  (`verify_dcap_evidence` vs `verify_verification_report` use divergent
  caller-binding styles in the same file).
- All 183 unit + integration tests green at HEAD.

## 17. Related Work: CodeRabbit and the Pipeline-vs-Agentic Debate

This section exists because CodeRabbit — the most-deployed AI code review
product on the market (~13M PRs processed, 8000+ paying customers as of early
2026) — has publicly argued **against** the L3 architecture this spec adopts.
We owe future readers a clear answer to "why are you doing the thing
CodeRabbit said doesn't work."

### 16.1 What CodeRabbit Does

- **Domain**: General-purpose PR code review. Polyglot. Diff-driven, second-scale latency, runs on every PR across GitHub/GitLab/Bitbucket.
- **Architecture**: Deterministic pipeline + selectively agentic. Their public position is *"we curate context — we don't wander."* They run **40+ static analyzers**, AST passes, symbol lookups, and historical-pattern filters **before** the LLM ever sees the code.
- **Code intelligence**: A production-grade codegraph for cross-file dependency reasoning, plus a **LanceDB** vector index for semantic retrieval ("find similar patterns across the repo").
- **Sub-agents**: Specialized LLM sub-agents per error class (security, style, performance) — each receives pre-curated context tuned to its category.
- **Infrastructure**: Google Cloud Run, peak ~200 instances at 8 vCPU / 32 GiB, ~10 PR webhooks per second.
- **Public stance**: Their blog [*Pipeline AI vs. Agentic AI*](https://www.coderabbit.ai/blog/pipeline-ai-vs-agentic-ai-for-code-reviews-let-the-model-reason-within-reason) explicitly identifies three failure modes of fully autonomous L3 agents:
  1. **Tool overuse** — calling everything "just in case", polluting the prompt
  2. **Context pollution** — redundant fetches dilute signal with noise
  3. **No reward signal** — no mechanism to distinguish helpful from useless tool calls

### 16.2 Side-by-Side Comparison

| Dimension | CodeRabbit | TEECheck (this design) |
|---|---|---|
| **Use case** | Incremental PR review, second-scale | Whole-repo deep audit, minutes-scale |
| **Trigger** | Diff-driven, runs on every PR | On-demand, full-repo |
| **Domain** | General (any language, any project) | Narrow (TEE attestation + key lifecycle, Rust-first) |
| **Architecture** | Pre-curated pipeline + classification sub-agents | L3 iterative planner with sandboxed action menu |
| **Static tools** | 40+ integrated (semgrep, codeql, linters, secret scanners) | grep + semgrep implemented; codeql/joern stub |
| **Code graph** | Production codegraph (cross-file dependencies) | regex graph today; tree-sitter outline in M2 |
| **Semantic search** | LanceDB vector index | Deliberately **not** chunk-RAG; hand-curated wiki + sink catalog |
| **Agent topology** | Sub-agents per error category, parallel | 3-agent **adversarial** chain (expert → challenger → verifier → arbiter) |
| **Context strategy** | Pre-curate everything before LLM sees it | LLM iteratively requests context via actions |
| **Latency budget** | Seconds (PR blocks merge) | Minutes (human waits) |
| **Cost per run** | Must be cents (10 req/s × 200 instances) | $0.4–1.2 acceptable |
| **Failure mode** | Slow PR queue, missed merge | Fall back to heuristic mode, run finishes |

### 16.3 Why TEECheck Can Afford L3 Where CodeRabbit Cannot

The economic and structural differences make L3 viable here even though
CodeRabbit correctly rejected it for their use case:

1. **Latency budget**. CodeRabbit must answer PRs in seconds and runs at
   10 req/s peak. They cannot afford 8 LLM rounds × per-round reasoning. We
   audit on demand, expect minute-scale runs, and have a 10-minute wall
   clock. The economics are completely different.

2. **Scope is narrow by design**. Our action menu is 9 actions; CodeRabbit's
   integrated tool space is 40+ analyzers + arbitrary IDE introspection.
   Our sink catalog is 13 categories in 3 groups. Their universe is "any
   bug in any language." **"Tool overuse" is bounded for us by construction**
   — there is not enough surface area for the LLM to wander far.

3. **A reward signal exists in our domain**. CodeRabbit says L3 has no
   structural reward signal. This is true for general code review where
   "is this issue worth flagging?" is a soft judgment. **Our domain has
   binary checkpoints**: a `reverse_trace` from `attestation_verify` either
   reaches an `attestation_policy_decision` site within depth N or it
   doesn't. The sink catalog itself is the reward structure CodeRabbit
   identifies as missing.

4. **Audit ≠ review**. PR review optimizes for *don't break the build* —
   missing one typo is fine, false positives are catastrophic (developer
   trust collapses). Audit optimizes for *find the one critical bug* —
   missing a typo is fine, missing an attestation bypass is catastrophic.
   These are different optimization targets and reward different
   architectures. Adversarial 3-agent + agentic exploration beats
   classification sub-agents at the audit objective.

5. **Auditor is in the loop**. CodeRabbit reviews a PR on its own; the
   developer reads the comments and accepts/dismisses. TEECheck produces
   review packets that a human auditor walks through interactively
   (`teecheck review`). The LLM does not need to be production-grade
   reliable — it needs to surface enough leads that a human auditor can
   triage in an afternoon. This shifts the precision/recall trade-off.

### 16.4 What We Should Steal from CodeRabbit

CodeRabbit has 13M PRs of operational data. Their lessons are real and
several apply to us regardless of architectural choice:

- **Codegraph is stronger than regex graph**. Our M2 tree-sitter outline
  is a midway point; a future M2.5 should consider rust-analyzer LSP for
  semantic call graphs. This brings us closer to CodeRabbit's codegraph
  fidelity without giving up the L3 loop.
- **Vector retrieval for the learned/ feedback loop**. Our
  `knowledge/learned/true-positive/` is currently a flat directory. Once
  history accumulates (50+ runs), a LanceDB-equivalent semantic index
  would let "past TPs in this category" become a prior on the candidate
  ranking. This is the closed-loop feedback that CodeRabbit gets from
  scale and we get from a smaller but curated index.
- **40+ static tools is a real number**. Our `staticcheck` adapter
  framework is built but only `grep` + `semgrep` are implemented;
  `codeql` and `joern` are stubs. CodeRabbit proves multi-tool integration
  is operationally viable at scale. Post-M5, we should genuinely implement
  the stubs — they become first-class actions in the planner menu.
- **Production observability is not optional**. CodeRabbit knows which
  sub-agents trigger most, which tools are over-used, where token budgets
  blow up. Our `04_planner/rounds.jsonl` must be designed for aggregation,
  not just debugging. M3 should include a small `teecheck planner-stats`
  command that summarizes rounds_used / tokens_used / termination_reason
  distributions across a directory of runs.

### 16.5 Plan B — Hybrid Architecture if M5 Live Test Fails

CodeRabbit's L3 warnings are real. If the M5 live smoke test against
oasis-sdk shows the planner spinning, producing low-quality candidates,
or routinely hitting the round budget without converging, we adopt the
following hybrid:

**Pre-stage (deterministic, CodeRabbit-style)**:
1. Load sink catalog
2. Run tree-sitter outline across the whole repo
3. For every category in every group, emit a **candidate seed** at every
   syntactic match point (no LLM)
4. Output: a `candidate_seeds.json` with rough hit locations, no scoring,
   no synthesis

**Agentic stage (TEECheck L3 narrowed)**:
1. Planner is initialized with `candidate_seeds.json` as part of its
   working memory (not the full action observation log)
2. The LLM's job becomes: **prioritize, reverse_trace, and synthesize**
   over the seeds. It may not "explore" outside the seed set in v1 of the
   hybrid.
3. Same evidence bundle output, same downstream (cases / expert / etc.)

This preserves the agentic synthesis (where LLM judgment matters) while
removing the open-ended exploration (where it tends to fail). It is
strictly less ambitious than the current L3 design but salvages the
investment in sink catalog, sandbox, and actions.

**Decision gate**: M5 live test results determine which path proceeds.
If the L3 design hits the success criteria in section 15, we stay on it.
If it does not, we cut over to Plan B before any further milestone investment.

### 16.6 Honest Remaining Risk

Even with the Plan B safety net, we are making a bet that **agentic
reverse-trace from a curated sink catalog finds bugs that CodeRabbit's
forward-pass classification would miss**. This bet is plausible because:

- Attestation bypasses are usually multi-hop reasoning chains ("verify is
  called, but the result is not bound to the session key three calls
  later") — exactly what reverse-trace plus LLM synthesis is good at.
- Forward-pass classifiers find local bugs (this line is wrong); audit
  bugs are often non-local (these three things together create the
  hole).

But "plausible" is not "proven". M5 is the moment of truth. This section
exists so future readers know we made the choice with eyes open, not by
ignoring the state of the art.
