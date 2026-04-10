# Agent LLM Modes And Inter-Agent Communication Design

## Summary

Add LLM modes to Verifier, Arbiter, and Curator (feedback) agents, and introduce
a lightweight message bus for runtime inter-agent communication. All agents share
a single LLM data source (`internal/llm/` OpenAI-compatible client) with
role-specific system prompts and output schemas.

## Agent LLM Mode Overview

```
LLM Data Source (internal/llm/ OpenAI-compatible client)
    ├── Expert Agent       — LLM mode exists
    ├── Challenger Agent   — LLM mode exists
    ├── Verifier Agent     — NEW: LLM mode
    ├── Arbiter Agent      — NEW: LLM mode
    └── Curator Agent      — NEW: LLM mode (feedback agent renamed)
```

Each agent shares the same `llm.Client`. They differ in system prompt, input
context, and output schema.

## Inter-Agent Communication

### Design Decisions

- **Interaction model:** Mixed — deterministic tool calls for code/data retrieval,
  LLM-to-LLM dialogue for reasoning clarification
- **Round limit:** Fixed maximum rounds per case (configurable, default 3)
- **Dialog persistence:** Full dialog saved to artifact directories as JSONL
- **Access control:** Fully open — any agent can query any other agent

### Message Protocol

```go
type Query struct {
    QueryID   string `json:"query_id"`
    FromAgent string `json:"from_agent"`
    ToAgent   string `json:"to_agent"`
    Kind      string `json:"kind"`      // "clarify" | "search" | "reanalyze"
    Question  string `json:"question"`
    Context   any    `json:"context,omitempty"`
}

type Response struct {
    QueryID   string   `json:"query_id"`
    FromAgent string   `json:"from_agent"`
    Answer    string   `json:"answer"`
    Facts     []string `json:"facts,omitempty"`
}

type Round struct {
    Query    Query    `json:"query"`
    Response Response `json:"response"`
}

type Dialog struct {
    CaseID string  `json:"case_id"`
    Rounds []Round `json:"rounds"`
}
```

### Bus Interface

```go
type AgentHandler func(ctx context.Context, q Query) (Response, error)

type Bus struct {
    handlers  map[string]AgentHandler
    maxRounds int
    dialogs   map[string]*Dialog  // case_id → accumulated dialog
}

func New(maxRounds int) *Bus
func (b *Bus) Register(agentName string, handler AgentHandler)
func (b *Bus) Ask(ctx context.Context, q Query) (Response, error)
func (b *Bus) GetDialog(caseID string) *Dialog
func (b *Bus) ResetDialog(caseID string)
```

`Ask` enforces the round limit: if the dialog for a given case already has
`maxRounds` rounds, it returns an error. The calling agent must then produce
its output with the information it has.

### Handler Types

**LLM Handler:** Wraps an LLM call. Receives the Query, builds a prompt from
the query question and context, calls `llm.Client.Generate()`, parses the
response into a `Response` struct. Used by Expert, Challenger, Verifier,
Arbiter, and Curator when in LLM mode.

Builder:

```go
func NewLLMHandler(client llm.Client, systemPrompt string, temperature float64) AgentHandler
```

The system prompt is role-specific. For example, when Expert receives a
clarification query, its system prompt is:

```
You are the Expert Agent in TEECheck. Another agent is asking you a question
about your analysis. Answer based on your role as the security hypothesis
expert. Return a JSON object with fields: answer (string), facts (array of strings).
```

**Tool Handler:** Deterministic operations. For example, Mapper receives a
`kind:"search"` query, runs the static check registry, and returns findings
as facts.

Builder:

```go
func NewToolHandler(name string, fn func(ctx context.Context, q Query) (Response, error)) AgentHandler
```

### Dialog Persistence

Each agent stage writes its accumulated dialog to its artifact directory
after completing all cases:

- `06_verifier/dialog-NNN.jsonl` — one line per round
- `07_arbiter/dialog-NNN.jsonl`
- `09_curator/dialog-NNN.jsonl`

The JSONL format matches `Round` struct — each line is one query-response pair.

## Verifier LLM Mode

### System Prompt

```
You are the Verifier Agent in TEECheck. Your role is to analyze static check
results and code evidence to arbitrate between the Expert's hypothesis and the
Challenger's objections. You can ask other agents for clarification.

Return a JSON object with fields:
- status: "corroborated" | "contested" | "inconclusive"
- checks_run: array of strings (what you checked)
- confirmed_facts: array of strings (evidence supporting the hypothesis)
- contradictions: array of strings (evidence against the hypothesis)
- notes: array of strings
- queries: array of objects (optional, each with: to_agent, kind, question)

If you need more information, populate the queries array. If you have enough
information, leave queries empty and provide your final judgment.
```

### Input Context

- Case pack (category, target files, symbols, obligations, snippets)
- Expert hypothesis (title, summary, suspected issue, supporting facts)
- Challenger challenge (exploit narrative, counter arguments, remaining questions)
- Static check findings from registry (tool_name, path, line, message, severity)

### Interaction Flow

1. Build initial prompt with all input context
2. Call LLM �� get response with optional `queries` array
3. If queries present and rounds remaining:
   - For each query, call `bus.Ask()` to route to target agent
   - Append responses to conversation context
   - Call LLM again with accumulated context
4. Repeat until no more queries or maxRounds reached
5. Parse final response into `VerificationMemo`
6. Write dialog to `06_verifier/dialog-NNN.jsonl`

### Heuristic Fallback

When in heuristic mode, the existing static-check-based logic runs without
the bus. No inter-agent communication in heuristic mode.

## Arbiter LLM Mode

### System Prompt

```
You are the Arbiter Agent in TEECheck. Your role is to synthesize all evidence
and produce a final judgment and human-readable review packet. You can ask other
agents for clarification.

Return a JSON object with fields:
- status: "no_issue_observed" | "needs_review" | "likely_issue" | "confirmed_candidate"
- severity: "high" | "medium" | "low"
- confidence: "high" | "medium" | "low"
- summary: string
- evidence: array of strings
- review_packet_markdown: string (the full review packet in markdown)
- queries: array of objects (optional, each with: to_agent, kind, question)
```

### Input Context

- Case pack
- Expert hypothesis
- Challenger challenge
- Verifier verification memo (including any dialog summary)

### Interaction Flow

Same loop as Verifier: build prompt → LLM → optional queries → loop → final output.

Output: `FindingItem` JSON + review packet markdown.

### Heuristic Fallback

Existing `arbitrate()` function continues to work without the bus.

## Curator LLM Mode

### Subcommand

Rename `feedback` to `curator` (keep `feedback` as alias for backward compatibility).

```
teecheck curator --run-dir DIR --knowledge-root DIR [--mode heuristic|llm]
```

### System Prompt

```
You are the Curator Agent in TEECheck. Your role is to maintain the knowledge
base. Given a human review record and finding context, generate structured
knowledge updates. You can ask other agents about their reasoning.

Return a JSON object with fields:
- archive_content: string (markdown content for the learned/ archive page)
- wiki_updates: array of objects, each with:
  - action: "append" | "suggest_new"
  - page_path: string (relative path under knowledge root)
  - content: string (markdown content to append or full page content)
  - reason: string
- queries: array of objects (optional, each with: to_agent, kind, question)
```

### Input Context

- Review record (verdict, severity, tags, notes)
- Finding context (summary, status, files, evidence)
- Existing wiki pages (titles, tags, paths — not full bodies to save tokens)

### Interaction Flow

Same query loop. Curator may ask Expert "what was the core reasoning behind
this hypothesis?" or Arbiter "what was the key evidence for your judgment?"
to produce richer wiki content.

### Output

- `knowledge/learned/{true-positive,false-positive,review-memory}/{case_id}.md`
  — generated by LLM instead of template
- Wiki updates: LLM generates actual paragraph content instead of one-line
  references. Applied via append or suggested as new pages.

### Heuristic Fallback

Existing tag-matching logic and template-based archival continues to work.

## Config Changes

New fields in `Config`:

```go
ArbiterMode    string // --arbiter-mode heuristic|llm (default heuristic)
CuratorMode    string // --curator-mode heuristic|llm (default heuristic)
MaxDialogRounds int   // --max-dialog-rounds N (default 3)
```

Verifier already has `VerifierMode`.

Updates to `parseCollabRun`:

- Add `--arbiter-mode`, `--curator-mode`, `--max-dialog-rounds` flags
- Default all modes to `"heuristic"`

New subcommand parsers:

- `parseCurator` (same shape as `parseFeedback` plus `--mode` and LLM flags)
- `"curator"` and `"feedback"` both route to curator

Updates to `parseArbiter`:

- Add `--mode heuristic|llm` and LLM flags

## collabrun Orchestration Changes

`collabrun.Run()` creates the bus when any agent mode is LLM:

```go
bus := agentbus.New(cfg.MaxDialogRounds)

// Register LLM handlers for agents in LLM mode
if expertMode == "llm" {
    bus.Register("expert-001", agentbus.NewLLMHandler(client, expertSystemPrompt, cfg.LLMTemp))
}
if challengerMode == "llm" {
    bus.Register("challenger-001", agentbus.NewLLMHandler(client, challengerSystemPrompt, cfg.LLMTemp))
}

// Register tool handler for mapper (always deterministic)
bus.Register("mapper", agentbus.NewToolHandler("mapper", mapperSearchHandler(registry)))

// Verifier, Arbiter, Curator use bus in LLM mode
verifier.RunWithBus(cfg, bus)   // new function, Run() still works without bus
arbiter.RunWithBus(cfg, bus)
curator.RunWithBus(cfg, bus)
```

Agents in heuristic mode: existing `Run(cfg)` functions unchanged. No bus needed.

Agents in LLM mode: new `RunWithBus(cfg, bus)` functions that use the bus
for inter-agent queries.

## File Layout

### New Files

| File | Responsibility |
|------|---------------|
| `internal/agentbus/bus.go` | Bus, Query, Response, Dialog, Round types |
| `internal/agentbus/bus_test.go` | Tests for bus routing and round limiting |
| `internal/agentbus/handlers.go` | NewLLMHandler, NewToolHandler builders |
| `internal/agentbus/handlers_test.go` | Tests for handler construction |

### Modified Files

| File | Changes |
|------|---------|
| `internal/verifier/run.go` | Add `RunWithBus()` with LLM query loop |
| `internal/arbiter/run.go` | Add `RunWithBus()` with LLM mode and query loop |
| `internal/feedback/run.go` | Rename to curator, add `RunWithBus()` with LLM mode |
| `internal/config/config.go` | Add ArbiterMode, CuratorMode, MaxDialogRounds; add curator parser |
| `cmd/teecheck/main.go` | Add curator routing, pass bus to agents |
| `internal/collabrun/run.go` | Create bus, register handlers, call RunWithBus |
| `internal/runfs/paths.go` | Add `CuratorDir()` path (09_curator) |

### Artifact Directory Addition

```
runs/{run-id}/
├── ... (00-08 unchanged)
└── 09_curator/
    ├── learned-NNN.json    # curator output per review record
    └── dialog-NNN.jsonl    # curator dialog log
```

Dialog files also added to 06_verifier/ and 07_arbiter/ when in LLM mode.
