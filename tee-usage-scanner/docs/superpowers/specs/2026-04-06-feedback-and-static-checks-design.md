# Human Feedback And Static Check Integration Design

## Summary

Two features extending the TEECheck collaborative harness:

1. Pluggable static analysis adapter framework with grep and Semgrep implementations
2. Interactive CLI human review with feedback writeback to the knowledge layer

## 1. Static Check Adapter Framework

### Core Interface

`internal/staticcheck/adapter.go`:

```go
type CheckRequest struct {
    RepoRoot    string
    TargetFiles []string
    Keywords    []string
    RuleIDs     []string
    Category    string
    ExtraArgs   map[string]string
}

type CheckFinding struct {
    ToolName  string `json:"tool_name"`
    RuleID    string `json:"rule_id,omitempty"`
    Path      string `json:"path"`
    StartLine int    `json:"start_line"`
    EndLine   int    `json:"end_line,omitempty"`
    Message   string `json:"message"`
    Severity  string `json:"severity,omitempty"`
    Snippet   string `json:"snippet,omitempty"`
}

type Adapter interface {
    Name() string
    Available() bool
    Run(ctx context.Context, req CheckRequest) ([]CheckFinding, error)
}
```

### Registry

`internal/staticcheck/registry.go`:

- `NewRegistry()` — empty registry
- `NewDefaultRegistry()` — registers all known adapters (grep, semgrep, codeql, joern)
- `Register(a Adapter)`
- `Get(name string) (Adapter, bool)`
- `Available() []string` — returns names of installed tools
- `RunAll(ctx, req) ([]CheckFinding, error)` — runs all available adapters
- `RunByName(ctx, name, req) ([]CheckFinding, error)` — runs one by name

### Adapter Implementations

**Grep** (`internal/staticcheck/grep/adapter.go`):

- Refactors existing `tools.LocalAdapter` search logic
- `Name()` returns `"grep"`, `Available()` always `true`
- Original `tools.LocalAdapter` preserved for backward compatibility, delegates internally

**Semgrep** (`internal/staticcheck/semgrep/adapter.go`):

- `Available()` checks `semgrep --version` is executable
- `Run()` builds command: `semgrep --json --config=auto --include=<files>` or specified rules
- Parses Semgrep JSON output, maps to `CheckFinding`
- Supports `ExtraArgs["config"]` for custom rule paths

**CodeQL** (`internal/staticcheck/codeql/adapter.go`):

- Stub only. `Available()` returns `false`, `Run()` returns `ErrNotImplemented`
- Reserved for future implementation

**Joern** (`internal/staticcheck/joern/adapter.go`):

- Stub only. `Available()` returns `false`, `Run()` returns `ErrNotImplemented`
- Reserves `ExtraArgs["cpg_path"]` for pre-generated CPG file path

### Config Changes

New field in `Config`:

```go
StaticTools string // --static-tools "grep,semgrep" or "auto" or "none"
```

Semantics:

- `"auto"` (default): use all adapters where `Available() == true`
- `"grep,semgrep"`: use only specified adapters, warn if unavailable
- `"none"`: skip all static checks

### Pipeline Integration

Any stage can create a registry and call adapters on demand. No forced coupling.

The Verifier is the most natural consumer: replace the hardcoded TODO/FIXME
scanning in `buildMemo()` with registry-based adapter calls. Results feed into
`VerificationMemo.ChecksRun` and `ConfirmedFacts`.

Mapper and other stages can also call adapters for enrichment when beneficial.

## 2. Interactive Human Review

### Subcommand

```
teecheck review --run-dir DIR [--knowledge-root DIR]
```

### Interaction Flow

Loads `07_arbiter/packets/review-NNN.md` and `07_arbiter/findings.json`.
Presents each case interactively:

1. Display case summary (case ID, category, priority, arbiter status, confidence)
2. Display hypothesis, challenger view, verification status
3. Prompt for verdict: `[c]onfirm / [d]ismiss / [i]nconclusive / [s]kip / [q]uit`
4. Prompt for optional severity override
5. Prompt for tags (comma-separated)
6. Prompt for free-text notes
7. Save and move to next case

### Data Structure

New type in `artifacts/types.go`:

```go
type ReviewRecord struct {
    SchemaVersion string   `json:"schema_version"`
    CaseID        string   `json:"case_id"`
    FindingID     string   `json:"finding_id"`
    Verdict       string   `json:"verdict"`
    Severity      string   `json:"severity"`
    Tags          []string `json:"tags,omitempty"`
    Notes         string   `json:"notes,omitempty"`
    ReviewerID    string   `json:"reviewer_id,omitempty"`
    ReviewedAt    string   `json:"reviewed_at"`
}
```

### Output

- `08_review/review-NNN.json` — one per case
- `08_review/review_records.jsonl` — append-only stream of all reviews

### Package Structure

`internal/review/`:

- `run.go` — main flow: load packets and findings, iterate, write results
- `prompt.go` — terminal interaction (bufio.Scanner on stdin, no TUI dependency)
- `display.go` — format and render review packet summary to terminal

### runfs Changes

```go
func ReviewDir(runDir string) string        // 08_review
func ReviewRecordsPath(runDir string) string // 08_review/review_records.jsonl
```

## 3. Feedback Writeback To Knowledge

### Subcommand

```
teecheck feedback --run-dir DIR --knowledge-root DIR
```

Automatically runs after `teecheck review` completes. Can also be run
independently.

### Package Structure

`internal/feedback/`:

- `run.go` — read review records, archive to learned, suggest wiki updates

### Archival To `knowledge/learned/`

Route by verdict:

- `confirmed` → `knowledge/learned/true-positive/{case_id}.md`
- `dismissed` → `knowledge/learned/false-positive/{case_id}.md`
- `inconclusive` → `knowledge/learned/review-memory/{case_id}.md`

Each file contains:

```markdown
# {case_id}

- Verdict: confirmed
- Severity: high
- Tags: attestation, freshness, replay
- Reviewed: 2026-04-06T15:30:00Z

## Notes

{reviewer notes}

## Context

- Hypothesis: {title}
- Challenger stance: {reviewer_stance}
- Verifier status: {status}
- Files: {target files}
```

### Wiki Update Suggestions

Feedback matches review record tags against existing wiki pages:

- Tags match existing wiki page → append a `## Learned` entry at the bottom
  referencing the case ID and conclusion
- Tags match no wiki page → print suggestion to stdout:
  `Suggest new wiki page: obligations/{tag}.md` but do NOT auto-create

Human retains control over wiki content. Feedback only appends and suggests.

### Orchestration

`collab-run` does NOT automatically chain into `review` (review is interactive).

Intended workflow:

```bash
teecheck collab-run --repo-url ... --local-path ... --commit ... --graph-json ...
teecheck review --run-dir runs/xxx
# feedback runs automatically after review completes
# or independently:
teecheck feedback --run-dir runs/xxx --knowledge-root knowledge
```

## File Layout Summary

New directories and files:

```
internal/
├── staticcheck/
│   ├── adapter.go          # Interface + CheckRequest + CheckFinding
│   ├── registry.go         # Registry + NewDefaultRegistry
│   ├── grep/
│   │   └── adapter.go      # Grep adapter (refactored from tools.LocalAdapter)
│   ├── semgrep/
│   │   └── adapter.go      # Semgrep adapter
│   ├── codeql/
│   │   └── adapter.go      # Stub
│   └── joern/
│       └── adapter.go      # Stub
├── review/
│   ├── run.go              # Interactive review flow
│   ├── prompt.go           # Terminal I/O
│   └── display.go          # Packet rendering
└── feedback/
    └── run.go              # Learned archival + wiki suggestions
```

Config changes: `StaticTools string` field, `--static-tools` flag.

runfs changes: `ReviewDir()`, `ReviewRecordsPath()`.

artifacts changes: `ReviewRecord` type.

CLI changes: `review` and `feedback` subcommands in config parser and main.
