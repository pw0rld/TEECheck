# TEECheck

A case-driven, multi-agent audit harness for TEE (Trusted Execution Environment)
security research. TEECheck uses an L3 LLM planner plus a 4-agent adversarial
review chain to find real attestation and key-lifecycle issues in trusted code.

## Optional: CodeQL

The scanner runs without CodeQL, but the deterministic fact layer — the
bottom, non-challengeable tier of the three-tier evidence model — stays
empty: `fact_layer_query` returns `status: unsupported` and every finding
rests on LLM judgement alone.

Installing it is ~551 MB to download, 1.7 GB on disk, and about two minutes
to verify end to end. See **[docs/SETUP_CODEQL.zh-CN.md](../docs/history/SETUP_CODEQL.zh-CN.md)**
for the measured numbers, the install steps, an end-to-end verification, and
the five known limitations (chief among them: only one of the nineteen TWE
entries currently has an executable query).

The bundle must never be committed — it exceeds GitHub's 100 MB per-file
limit. `/tools/` is gitignored for that reason.

## Quick Start

```bash
# Build
cd tee-usage-scanner
go build -o teecheck ./cmd/teecheck/

# Scan a repository — the L3 planner runs end to end through the
# 4-agent pipeline (expert → challenger → verifier → arbiter)
./teecheck run https://github.com/oasisprotocol/oasis-sdk \
  --llm-base-url http://your-api:8080/v1 \
  --llm-api-key sk-your-key \
  --llm-model your-model \
  --focus tee --max-cases 4

# Scan with the built-in GLM preset (z.ai Anthropic-compatible endpoint)
./teecheck run https://github.com/oasisprotocol/oasis-sdk \
  --llm-provider glm \
  --llm-api-key your-zai-key \
  --llm-model glm-4.7 \
  --focus tee --max-cases 4

# Equivalent shorthand
./teecheck plan https://github.com/mobilecoinfoundation/mobilecoin \
  --llm-provider glm --llm-api-key your-zai-key --focus tee --max-cases 4
```

See [`examples/mobilecoin-l3-v17-scan/REPORT.md`](examples/mobilecoin-l3-v17-scan/REPORT.md)
for a full annotated GLM run on `mobilecoinfoundation/mobilecoin` (v17 is the
first run where the planner autonomously used `reverse_trace` to pivot from
low-level SGX wrappers into the AKE trust-decision code). Earlier runs are
preserved under `examples/mobilecoin-l3-v1{3,4}-scan/`.

## How It Works

The pipeline is **L3 planner → 4-agent adversarial review**:

```
teecheck run <url-or-path>
    |
    v
+-- Preprocessor ----+   project profile, languages, frameworks
+--------+-----------+
         |
         v
+-- L3 Planner ------+   iterative LLM agent with action budget
|  ripgrep / read    |   - sink_catalog_lookup → ripgrep → outline
|  tree_sitter_*     |   - reverse_trace walks call graph backward
|  reverse_trace     |   - observed-paths whitelist blocks hallucinated
|  sink_catalog_*    |     file paths in the final round
|  done              |   → 04_planner/evidence_bundle.json
+--------+-----------+
         |
         v   → 03_cases
+-- Expert ----------+   generates security hypotheses per case
+-- Challenger ------+   adversarial objections to each hypothesis
+-- Verifier --------+   re-grounds each claim against the source
+-- Arbiter ---------+   final findings + human-readable review packets
         |
         v
    Final Report (07_arbiter/packets/*.md)
```

The L3 planner replaces the old keyword-scoring hotspot picker. It loads a
curated **sink catalog** (`knowledge/sinks/rust.json`, three groups:
attestation, TEE syscalls, key lifecycle) and lets the LLM iteratively decide
which files to read, which symbols to outline, and which call sites to trace
backward — under a four-dimensional budget (rounds / tokens / wall-clock /
per-action timeout). See [`docs/superpowers/specs/2026-04-11-llm-planner-design.md`](docs/superpowers/specs/2026-04-11-llm-planner-design.md)
for the full design.

### One Path

There is a single pipeline: the L3 planner picks what to investigate and every
agent is LLM-backed. The heuristic/keyword mode and the legacy scanner branch
were retired on 2026-07-31 — every run on disk had been LLM mode for months,
and keeping a second, untested semantics only hid defects.

**v1 is validated on GLM
only** — use `--llm-provider glm` with a z.ai API key (defaults to `glm-4.7`
via the Anthropic-compatible endpoint). An `openai` preset exists for any
OpenAI-compatible endpoint, but it is unvalidated in v1 and deferred to v2.
Transient 5xx / timeout errors are retried with backoff. Produces detailed
review packets, an evidence bundle, and a streaming `rounds.jsonl` for full
planner replay.

## Commands

### `teecheck run` (main command)

Runs the full pipeline on a repository: L3 planner plus the 4-agent
adversarial review chain.

### `teecheck plan`

An alias for `teecheck run`, kept because scripts use it.

```bash
teecheck run <url-or-path> [flags]
```

**Arguments:**
- `<url-or-path>` - GitHub URL (auto-clones) or local directory path

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--focus` | `tee` | Audit focus: `tee`, `runtime`, `attestation` |
| `--max-cases` | `12` | Maximum case packs to generate |
| `--max-hotspots` | `12` | Maximum hotspots to identify |
| `--max-dialog-rounds` | `3` | Max inter-agent dialog rounds (LLM mode) |
| `--run-id` | auto | Stable run identifier |
| `--output-dir` | `runs` | Output directory for run artifacts |
| `--knowledge-root` | `knowledge` | Knowledge wiki root directory |
| `--static-tools` | `auto` | Static tools: `auto`, `none`, or `grep,semgrep` |
| `--llm-provider` | `openai` | Provider preset: `glm` (validated in v1) or `openai` (unvalidated) |
| `--llm-base-url` | env | Provider base URL; `glm` fills Anthropic-compatible defaults automatically |
| `--llm-api-key` | env | API key |
| `--llm-model` | env | Model name |
| `--llm-temperature` | `0.2` | Sampling temperature |

**Environment variables** (alternative to flags):
- `TEECHECK_LLM_BASE_URL`
- `TEECHECK_LLM_API_KEY`
- `TEECHECK_LLM_MODEL`

Provider presets:
- `glm` (**validated in v1**): uses `https://api.z.ai/api/anthropic` by default and falls back to model `glm-4.7` when `--llm-model` is omitted.
- `openai` (**experimental, unvalidated**): generic OpenAI-compatible mode. Bring your own `--llm-base-url` if needed. Not part of v1 scope — see design spec §15.

### `teecheck review` (optional, interactive)

Interactive human review of findings.

```bash
teecheck review --run-dir runs/<run-id>
```

Walks through each finding interactively:
- Display review packet summary
- Prompt for verdict: confirm / dismiss / inconclusive / skip
- Prompt for severity override, tags, notes
- Save review records to `08_review/`

### `teecheck curator` (optional, knowledge writeback)

Archives review outcomes and updates the knowledge wiki.

```bash
teecheck curator --run-dir runs/<run-id> --knowledge-root knowledge \
  --llm-base-url ... --llm-api-key ... --llm-model ...
```

### Legacy commands

The original fine-grained commands still work:

```bash
teecheck knowledge-init    # Initialize knowledge directories
teecheck preprocess ...    # Project profiling only
teecheck expert ...        # Hypothesis generation only
teecheck challenge ...     # Hypothesis challenging only
teecheck verifier ...      # Evidence verification only
teecheck arbiter ...       # Final arbitration only
```

## Output Structure

```
runs/<run-id>/
├── 00_manifest.json                   # Run metadata
├── 01_profile/project_profile.json    # Languages, frameworks, paths
├── 03_cases/case-NNN.json             # Bounded review cases
├── 04_expert/hypothesis-NNN.json      # Security hypotheses
├── 04_planner/
│   ├── evidence_bundle.json           # Planner candidates + sink hits
│   ├── rounds.jsonl                   # Streaming per-round transcript
│   └── sink_hits.json                 # Sink catalog hits
├── 05_challenger/challenge-NNN.json   # Challenger objections
├── 06_verifier/verify-NNN.json        # Verification memos
├── 07_arbiter/
│   ├── findings.json                  # Final findings
│   └── packets/review-NNN.md          # Human-readable review packets
├── 08_review/                         # (optional) Human review records
└── 09_curator/                        # (optional) Knowledge updates
```

## Code Graph Generation

TEECheck auto-generates a code structure graph using pluggable adapters:

| Adapter | Status | What it does |
|---------|--------|-------------|
| **regex** | Implemented | Regex-based extraction of functions/structs/classes across Rust, Go, TypeScript, Python, Solidity |
| **semgrep** | Stub (runs if installed) | Pattern-based precise extraction |
| **codeql** | Stub | Data flow analysis, call graph extraction |
| **joern** | Stub | CPG-based cross-procedure analysis |

In LLM mode, the L3 planner decides which tools to use based on the project profile and the sink catalog.

## Static Check Framework

Pluggable static analysis with the same adapter pattern:

| Adapter | Status | What it does |
|---------|--------|-------------|
| **grep** | Implemented | Keyword search across files |
| **semgrep** | Implemented | Rule-based pattern matching |
| **codeql** | Stub | Deep data flow queries |
| **joern** | Stub | CPG queries |

## Knowledge Layer

TEECheck accumulates knowledge across runs:

```
knowledge/
├── raw/               # Source materials (CVEs, papers, SDK docs)
├── wiki/              # Curated security obligation pages
│   ├── obligations/   # Trust boundary, attestation, etc.
│   └── patterns/      # Authorization, caller binding, etc.
└── learned/           # Review outcomes
    ├── true-positive/
    ├── false-positive/
    └── review-memory/
```

This is intentionally **not** chunk-RAG. Knowledge is curated into stable wiki
pages that agents query during analysis.

## Inter-Agent Communication

In LLM mode, agents communicate through a message bus:

- **Verifier** can ask **Expert** or **Challenger** for clarification on their claims
- **Arbiter** can ask **Verifier** or the static-check tool handler for more evidence
- Dialog rounds are capped (default 3) to control cost
- All dialogs are persisted as JSONL for auditability

## Architecture

```
internal/
├── repofetch/       # Git clone / local path detection
├── scanner/         # Code graph generation (GraphAdapter framework)
│   ├── regex/       # Regex-based extractor
│   ├── semgrep/     # Semgrep adapter
│   ├── codeql/      # CodeQL stub
│   └── joern/       # Joern stub
├── pipeline/        # 3-agent orchestrator (teecheck run)
├── preprocessor/    # Project profiling
├── mapper/          # Repo structure mapping
├── hotspots/        # Hotspot identification
├── cases/           # Case pack generation
├── expert/          # Hypothesis generation
├── challenger/      # Hypothesis challenging
├── verifier/        # Evidence verification
├── arbiter/         # Final arbitration
├── staticcheck/     # Static analysis framework
│   ├── grep/        # Grep adapter
│   ├── semgrep/     # Semgrep adapter
│   ├── codeql/      # CodeQL stub
│   └── joern/       # Joern stub
├── agentbus/        # Inter-agent message bus
├── llm/             # OpenAI-compatible LLM client
├── review/          # Interactive human review
├── feedback/        # Knowledge writeback (curator)
├── knowledge/       # Wiki and learned knowledge
├── artifacts/       # JSON type definitions
├── runfs/           # Run directory helpers
└── config/          # CLI argument parsing
```

## Development

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Build binary
go build -o teecheck ./cmd/teecheck/

# Run live LLM test (requires API key)
TEECHECK_LLM_BASE_URL=http://your-api/v1 \
TEECHECK_LLM_API_KEY=sk-your-key \
TEECHECK_LLM_MODEL=your-model \
go test ./internal/llm/ -v -run TestLiveLLMDataSource
```

## Design Documents

- `docs/MULTI_AGENT_HARNESS.md` — Overall harness design
- `docs/ARCHITECTURE_RESERVATIONS.md` — Architectural constraints and sequencing
- `docs/superpowers/specs/` — Feature design specs
- `docs/superpowers/plans/` — Implementation plans
