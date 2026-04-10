# Three-Agent Pipeline And Simplified CLI Design

## Summary

Restructure TEECheck from a 6-stage serial pipeline into a 3-agent architecture
with automatic repo acquisition, AI-driven code graph generation, and a
single-command entry point.

## Simplified CLI

```bash
# Minimal — just a URL
teecheck run https://github.com/oasisprotocol/oasis-sdk

# Local path
teecheck run /path/to/repo

# With LLM
teecheck run https://github.com/oasisprotocol/oasis-sdk --mode llm \
  --llm-base-url http://18.177.142.134:8080/v1 \
  --llm-api-key sk-... --llm-model gpt-5.4

# Full options
teecheck run <url-or-path> \
  [--mode heuristic|llm] \
  [--focus tee|runtime|attestation] \
  [--max-cases N] \
  [--max-dialog-rounds N] \
  [--run-id ID] \
  [--output-dir DIR] \
  [--knowledge-root DIR]
```

`--mode llm` controls all agents at once. No per-agent mode flags needed.

## 1. Repo Acquisition (`internal/repofetch/`)

Detects whether input is a URL or local path.

- **URL** (starts with `http://`, `https://`, or `git@`): `git clone --depth 50`
  to a temp directory, read HEAD commit with `git rev-parse HEAD`
- **Local path**: use directly, read HEAD commit

Output: `localPath string, commit string, repoURL string`

Cleanup: if cloned to temp, the temp dir persists for the run duration.
The caller is responsible for cleanup after the pipeline completes.

## 2. AI-Driven Code Graph Generation

### Architecture

Graph generation is an **agent task**, not a hardcoded pipeline. The Scanner
agent uses LLM (when in LLM mode) to decide which tools to use and how to
combine their outputs. In heuristic mode, it uses all available tools
automatically.

### GraphAdapter Interface

Extends the existing `staticcheck` framework with a graph extraction capability.

```go
// internal/scanner/graph_adapter.go
type GraphAdapter interface {
    Name() string
    Available() bool
    ExtractGraph(ctx context.Context, req GraphRequest) (GraphResult, error)
}

type GraphRequest struct {
    RepoRoot  string
    Languages []string
    Focus     string
}

type GraphNode struct {
    ID       string `json:"id"`
    Kind     string `json:"kind"`     // "file", "function", "struct", "trait", "class", "contract"
    Name     string `json:"name"`
    Path     string `json:"path"`
    Language string `json:"language"`
}

type GraphEdge struct {
    Source string `json:"source"`
    Target string `json:"target"`
    Kind   string `json:"kind"`       // "defines", "calls", "depends_on", "references"
}

type GraphResult struct {
    Nodes []GraphNode `json:"nodes"`
    Edges []GraphEdge `json:"edges"`
}
```

### Built-in GraphAdapter Implementations

**Regex adapter** (`internal/scanner/regex/`):
- `Available()`: always true (no external dependency)
- Walks file tree, matches file extensions to language
- Per-language regex rules extract function/struct/class/trait definitions
- Cross-file symbol reference detection for call/dependency edges
- Built-in rules for: Rust, Go, TypeScript, Python, Solidity
- Unknown language files: file node only, no symbol extraction
- Skips: `.git/`, `vendor/`, `node_modules/`, `target/`, binary files

**Semgrep adapter** (`internal/scanner/semgrep/`):
- `Available()`: checks `semgrep --version`
- Uses semgrep pattern matching for precise symbol extraction
- Better at complex patterns (closures, generics, macros)

**CodeQL adapter** (`internal/scanner/codeql/`):
- Stub. `Available()` returns false.
- When implemented: creates database, runs graph extraction queries

**Joern adapter** (`internal/scanner/joern/`):
- Stub. `Available()` returns false.
- When implemented: generates CPG, extracts call graph and data flow

### Graph Generation Registry

```go
// internal/scanner/registry.go
type GraphRegistry struct {
    adapters map[string]GraphAdapter
    order    []string
}

func NewDefaultGraphRegistry() *GraphRegistry  // registers regex, semgrep, codeql, joern
func (r *GraphRegistry) Available() []string
func (r *GraphRegistry) RunAll(ctx, req) (GraphResult, error)           // merge all available
func (r *GraphRegistry) RunByName(ctx, name, req) (GraphResult, error)
```

### Graph Merge Logic

When multiple adapters produce results, merge by:
1. Deduplicate nodes by (path, name, kind)
2. Deduplicate edges by (source, target, kind)
3. Prefer richer metadata (e.g., CodeQL edge with data flow info over regex edge)

### LLM Mode: AI-Driven Tool Selection

In LLM mode, the Scanner agent:

1. Reads project profile (languages, frameworks, directory structure)
2. Receives list of available graph adapters
3. LLM decides tool plan:
   ```json
   {
     "tools": [
       {"name": "regex", "reason": "fast baseline scan"},
       {"name": "semgrep", "reason": "precise TEE pattern matching"}
     ]
   }
   ```
4. Executes tools in plan order
5. LLM reviews intermediate results, may request additional tools
6. LLM produces final merged graph or requests refinements

In heuristic mode: skip LLM, run all `Available()` adapters, auto-merge.

## 3. Three-Agent Pipeline (`internal/pipeline/`)

### Agent 1: Scanner

**Responsibility:** Acquire code, understand structure, identify security concerns.

**Steps:**
1. `repofetch` — clone or locate repo
2. `preprocessor.Run` — project profile
3. `scanner.Run` — generate graph JSON (AI-driven tool selection in LLM mode)
4. `mapper.Run` — repo map + hotspot index (using generated graph)
5. `cases.Run` — bounded case packs
6. Static checks via `staticcheck.Registry` (grep, semgrep)
7. `expert.Run` — security hypothesis per case

**Bus registration:** Tool handler for search requests from Reviewer.
When Reviewer asks Scanner "search for caller binding in verify.rs",
Scanner runs staticcheck adapters and returns findings as facts.

**Outputs:**
- `01_profile/project_profile.json`
- `02_graph/graph.json`
- `03_repo_map/repo_map.json`
- `04_hotspots/hotspot_index.json`
- `05_cases/case-NNN.json`
- `06_scanner/hypothesis-NNN.json`
- `06_scanner/static-NNN.json`

### Agent 2: Reviewer

**Responsibility:** Challenge hypotheses, verify evidence, ask Scanner for more.

**Steps:**
1. `challenger.Run` — attack each hypothesis from skeptic/attacker perspective
2. `verifier.Run` — arbitrate using static evidence + bus queries to Scanner
3. In LLM mode: may send multiple queries to Scanner via bus
   - "Search for X in file Y"
   - "Is there caller validation in the surrounding code?"
   - "What does function Z do?"

**Bus registration:** LLM handler so Auditor can ask Reviewer for clarification.

**Outputs:**
- `07_reviewer/challenge-NNN.json`
- `07_reviewer/verify-NNN.json`
- `07_reviewer/dialog-NNN.jsonl`

### Agent 3: Auditor

**Responsibility:** Final judgment, report quality review.

**Steps:**
1. `arbiter.Run` — synthesize all evidence, produce final verdict
2. In LLM mode: may query Scanner or Reviewer via bus for clarification
3. Generate human-readable review packets
4. Produce findings.json with status/severity/confidence

**Outputs:**
- `08_auditor/findings.json`
- `08_auditor/packets/review-NNN.md`
- `08_auditor/dialog-NNN.jsonl`

### Optional Human Stages (unchanged)

```bash
teecheck review --run-dir runs/xxx          # interactive human review
teecheck curator --run-dir runs/xxx         # knowledge writeback
```

Outputs to `09_review/` and `10_curator/` respectively.

## 4. Pipeline Orchestration

```go
// internal/pipeline/run.go
func Run(cfg config.Config) (string, error) {
    // 1. Repo acquisition
    localPath, commit, repoURL := repofetch.Fetch(cfg.Target)

    // 2. Init run directory
    runDir := runinit.Run(cfg, time.Now())

    // 3. Build bus (if any agent in LLM mode)
    bus := buildBus(cfg)

    // 4. Scanner agent
    scanner.RunAgent(cfg, bus, runDir, localPath, commit)
    // Registers itself on bus as tool handler

    // 5. Reviewer agent
    reviewer.RunAgent(cfg, bus, runDir)
    // Registers itself on bus as LLM handler

    // 6. Auditor agent
    auditor.RunAgent(cfg, bus, runDir)

    // 7. Print summary
    printSummary(runDir)

    return runDir, nil
}
```

## 5. Config Changes

New `Config` fields:

```go
Target string  // URL or local path (positional arg)
Mode   string  // "heuristic" or "llm" — controls all agents at once
```

New `parseRun` function handles the simplified CLI. Internally maps `--mode llm`
to setting ExpertMode, ChallengeMode, VerifierMode, ArbiterMode, CuratorMode
all to "llm".

## 6. Artifact Directory Layout

```
runs/{run-id}/
├── 00_manifest.json
├── 01_profile/project_profile.json
├── 02_graph/graph.json                  ← NEW: auto-generated
├── 03_repo_map/repo_map.json
├── 04_hotspots/hotspot_index.json
├── 05_cases/case-NNN.json
├── 06_scanner/
│   ├── hypothesis-NNN.json
│   └── static-NNN.json
├── 07_reviewer/
│   ├── challenge-NNN.json
│   ├── verify-NNN.json
│   └── dialog-NNN.jsonl
├── 08_auditor/
│   ├── findings.json
│   ├── packets/review-NNN.md
│   └── dialog-NNN.jsonl
├── 09_review/                           (optional, human)
└── 10_curator/                          (optional, knowledge)
```

## 7. Relationship To Existing Code

**Fully reused (no changes):**
- `internal/preprocessor/` — project profiling
- `internal/mapper/` — repo map + hotspot generation
- `internal/hotspots/` — hotspot ranking
- `internal/cases/` — case pack generation
- `internal/expert/` — hypothesis generation
- `internal/challenger/` — hypothesis challenging
- `internal/verifier/` — evidence verification
- `internal/arbiter/` — final arbitration
- `internal/staticcheck/` — static check framework + all adapters
- `internal/agentbus/` — inter-agent communication
- `internal/llm/` — LLM client
- `internal/knowledge/` — knowledge layer
- `internal/review/` — interactive review
- `internal/feedback/` — curator/feedback
- `internal/runfs/` — run filesystem helpers
- `internal/artifacts/` — JSON types

**New packages:**
- `internal/repofetch/` — repo URL/path detection and cloning
- `internal/scanner/` — AI-driven graph generation with GraphAdapter framework
- `internal/pipeline/` — 3-agent orchestration and `teecheck run` entry point

**Modified:**
- `internal/config/config.go` — add `parseRun`, `Target`, `Mode` fields
- `internal/runfs/paths.go` — add new directory paths (GraphDir, ScannerDir, etc.)
- `cmd/teecheck/main.go` — add `"run"` command routing

**Preserved:**
- `collab-run` and all existing subcommands remain functional. `teecheck run`
  is a new entry point that internally reuses the same stage implementations.

## 8. New File Layout

```
internal/
├── repofetch/
│   ├── fetch.go              # URL/path detection, git clone
│   └── fetch_test.go
├── scanner/
│   ├── graph_adapter.go      # GraphAdapter interface, GraphRequest/Result/Node/Edge
│   ├── registry.go           # GraphRegistry
│   ├── registry_test.go
│   ├── scan.go               # Main scan orchestration (heuristic + LLM modes)
│   ├── scan_test.go
│   ├── merge.go              # Graph merge/dedup logic
│   ├── regex/
│   │   ├── adapter.go        # Regex-based graph extraction
│   │   ├── adapter_test.go
│   │   └── langs.go          # Per-language regex rules
│   ├── semgrep/
│   │   └── adapter.go        # Semgrep graph extraction (Available() checks binary)
│   ├── codeql/
│   │   └── adapter.go        # Stub
│   └── joern/
│       └── adapter.go        # Stub
├── pipeline/
│   ├── run.go                # 3-agent orchestration
│   ├── run_test.go
│   ├── scanner_agent.go      # Scanner agent logic
│   ├── reviewer_agent.go     # Reviewer agent logic
│   └── auditor_agent.go      # Auditor agent logic
```
