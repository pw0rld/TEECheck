# TEECheck

A case-driven, multi-agent audit harness for TEE (Trusted Execution Environment)
security research. TEECheck uses AI agents to collaboratively analyze codebases
for security issues in trusted execution environments.

## Quick Start

```bash
# Build
cd tee-usage-scanner
go build -o teecheck ./cmd/teecheck/

# Scan a repository (heuristic mode - no LLM needed)
./teecheck run https://github.com/oasisprotocol/oasis-sdk --focus tee

# Scan a local path
./teecheck run /path/to/repo --focus tee --max-cases 4

# Scan with LLM mode (much higher quality analysis)
./teecheck run https://github.com/oasisprotocol/oasis-sdk --mode llm \
  --llm-base-url http://your-api:8080/v1 \
  --llm-api-key sk-your-key \
  --llm-model your-model \
  --focus tee --max-cases 4
```

## How It Works

TEECheck uses a 3-agent pipeline:

```
teecheck run <url-or-path>
    |
    v
+-- Scanner Agent --+
|  Clone repo        |
|  Generate code     |
|  graph (auto)      |
|  Run static checks |
|  Identify hotspots |
|  Generate security |
|  hypotheses        |
+--------+-----------+
         |
         v  (Reviewer can query Scanner for more evidence)
+-- Reviewer Agent -+
|  Challenge each    |
|  hypothesis        |
|  Verify evidence   |
|  Ask Scanner for   |
|  additional code   |
|  searches          |
+--------+-----------+
         |
         v  (Auditor can query Scanner or Reviewer)
+-- Auditor Agent --+
|  Synthesize all    |
|  evidence          |
|  Final judgment    |
|  Generate review   |
|  packets           |
+--------+-----------+
         |
         v
    Final Report
```

### Two Modes

**Heuristic mode** (default): Fast, no LLM needed. Uses pattern matching and
heuristic rules. Good for quick scans.

**LLM mode** (`--mode llm`): Much higher quality. Each agent uses an
OpenAI-compatible LLM to reason about security properties. Agents can query each
other through a message bus for additional context. Produces detailed review
packets with executive summaries, risk assessments, and recommended follow-ups.

## Commands

### `teecheck run` (main command)

Runs the full 3-agent pipeline on a repository.

```bash
teecheck run <url-or-path> [flags]
```

**Arguments:**
- `<url-or-path>` - GitHub URL (auto-clones) or local directory path

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `heuristic` | Agent mode: `heuristic` or `llm` |
| `--focus` | `tee` | Audit focus: `tee`, `runtime`, `attestation` |
| `--max-cases` | `12` | Maximum case packs to generate |
| `--max-hotspots` | `12` | Maximum hotspots to identify |
| `--max-dialog-rounds` | `3` | Max inter-agent dialog rounds (LLM mode) |
| `--run-id` | auto | Stable run identifier |
| `--output-dir` | `runs` | Output directory for run artifacts |
| `--knowledge-root` | `knowledge` | Knowledge wiki root directory |
| `--static-tools` | `auto` | Static tools: `auto`, `none`, or `grep,semgrep` |
| `--llm-base-url` | env | OpenAI-compatible API base URL |
| `--llm-api-key` | env | API key |
| `--llm-model` | env | Model name |
| `--llm-temperature` | `0.2` | Sampling temperature |

**Environment variables** (alternative to flags):
- `TEECHECK_LLM_BASE_URL`
- `TEECHECK_LLM_API_KEY`
- `TEECHECK_LLM_MODEL`

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
# Heuristic
teecheck curator --run-dir runs/<run-id> --knowledge-root knowledge

# LLM (generates richer wiki content)
teecheck curator --run-dir runs/<run-id> --mode llm \
  --llm-base-url ... --llm-api-key ... --llm-model ...
```

### Legacy commands

The original fine-grained commands still work:

```bash
teecheck collab-run ...    # 6-stage serial pipeline
teecheck knowledge-init    # Initialize knowledge directories
teecheck preprocess ...    # Project profiling only
teecheck mapper ...        # Repo mapping only
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
├── 02_graph/graph.json                # Auto-generated code structure graph
├── 03_repo_map/repo_map.json          # Module boundaries, trust surfaces
├── 04_hotspots/hotspot_index.json     # Ranked security hotspots
├── 05_cases/case-NNN.json             # Bounded review cases
├── 04_expert/hypothesis-NNN.json      # Security hypotheses
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

In LLM mode, the Scanner agent can decide which tools to use based on the project profile.

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

- **Reviewer** can ask **Scanner** to search for specific code patterns
- **Auditor** can ask **Reviewer** or **Scanner** for clarification
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
