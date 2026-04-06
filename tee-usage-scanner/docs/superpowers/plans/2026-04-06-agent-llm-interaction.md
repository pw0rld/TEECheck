# Agent LLM Modes And Inter-Agent Communication — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a lightweight message bus for inter-agent communication, LLM modes for Verifier/Arbiter/Curator agents, and an integration test that validates real LLM data source connectivity.

**Architecture:** A new `agentbus` package provides Query/Response message types and a Bus that routes queries to registered agent handlers. Handlers are either LLM-backed (call `llm.Client.Generate`) or tool-backed (run deterministic operations like grep). Each agent's `Run` function gains a `RunWithBus` variant for LLM mode. Dialogs are persisted as JSONL artifacts.

**Tech Stack:** Go 1.25, stdlib only, existing `internal/llm` OpenAI-compatible client.

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `internal/agentbus/types.go` | Query, Response, Round, Dialog types |
| `internal/agentbus/bus.go` | Bus struct, Register, Ask, GetDialog, ResetDialog |
| `internal/agentbus/bus_test.go` | Tests for bus routing and round limiting |
| `internal/agentbus/handlers.go` | NewLLMHandler, NewToolHandler builders |
| `internal/agentbus/handlers_test.go` | Tests for LLM handler (httptest mock) and tool handler |
| `internal/llm/live_test.go` | Live LLM connectivity test (skipped without API key) |

### Modified Files

| File | Changes |
|------|---------|
| `internal/verifier/run.go` | Add `RunWithBus()` with LLM query loop |
| `internal/arbiter/run.go` | Add `RunWithBus()` with LLM mode and query loop |
| `internal/feedback/run.go` | Add `RunWithBus()` with LLM mode (curator) |
| `internal/config/config.go` | Add ArbiterMode, CuratorMode, MaxDialogRounds fields and flags |
| `internal/runfs/paths.go` | Add `CuratorDir()` path |
| `internal/collabrun/run.go` | Create bus, register handlers, call RunWithBus when LLM |
| `cmd/teecheck/main.go` | Add `curator` command routing |

---

## Task 1: Agent Bus Types

**Files:**
- Create: `internal/agentbus/types.go`

- [ ] **Step 1: Create types file**

```go
// internal/agentbus/types.go
package agentbus

type Query struct {
	QueryID   string `json:"query_id"`
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Kind      string `json:"kind"`
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

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/agentbus/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/agentbus/types.go
git commit -m "feat(agentbus): add Query, Response, Round, Dialog types"
```

---

## Task 2: Bus Implementation

**Files:**
- Create: `internal/agentbus/bus.go`
- Create: `internal/agentbus/bus_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/agentbus/bus_test.go
package agentbus_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
)

func TestBusRoutesQuery(t *testing.T) {
	bus := agentbus.New(3)
	bus.Register("expert-001", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "expert-001",
			Answer:    "The attestation check is missing because...",
			Facts:     []string{"verify.rs:42 has no timestamp check"},
		}, nil
	})

	resp, err := bus.Ask(context.Background(), agentbus.Query{
		QueryID:   "q-001",
		FromAgent: "verifier-001",
		ToAgent:   "expert-001",
		Kind:      "clarify",
		Question:  "Why do you think attestation is missing?",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.FromAgent != "expert-001" {
		t.Fatalf("expected from expert-001, got %s", resp.FromAgent)
	}
	if len(resp.Facts) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(resp.Facts))
	}
}

func TestBusUnknownAgent(t *testing.T) {
	bus := agentbus.New(3)
	_, err := bus.Ask(context.Background(), agentbus.Query{
		QueryID: "q-001",
		ToAgent: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestBusRoundLimit(t *testing.T) {
	bus := agentbus.New(2)
	bus.Register("target", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{QueryID: q.QueryID, FromAgent: "target", Answer: "ok"}, nil
	})

	caseID := "case-001"

	// Round 1 — should succeed
	_, err := bus.AskForCase(context.Background(), caseID, agentbus.Query{
		QueryID: "q-1", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q1",
	})
	if err != nil {
		t.Fatalf("round 1 failed: %v", err)
	}

	// Round 2 — should succeed
	_, err = bus.AskForCase(context.Background(), caseID, agentbus.Query{
		QueryID: "q-2", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q2",
	})
	if err != nil {
		t.Fatalf("round 2 failed: %v", err)
	}

	// Round 3 — should fail (limit is 2)
	_, err = bus.AskForCase(context.Background(), caseID, agentbus.Query{
		QueryID: "q-3", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q3",
	})
	if err == nil {
		t.Fatal("expected error for round limit exceeded")
	}
}

func TestBusDialogPersistence(t *testing.T) {
	bus := agentbus.New(5)
	bus.Register("target", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{QueryID: q.QueryID, FromAgent: "target", Answer: "answer"}, nil
	})

	_, _ = bus.AskForCase(context.Background(), "case-001", agentbus.Query{
		QueryID: "q-1", FromAgent: "caller", ToAgent: "target", Kind: "clarify", Question: "q1",
	})

	dialog := bus.GetDialog("case-001")
	if dialog == nil {
		t.Fatal("expected dialog for case-001")
	}
	if len(dialog.Rounds) != 1 {
		t.Fatalf("expected 1 round, got %d", len(dialog.Rounds))
	}
	if dialog.Rounds[0].Query.Question != "q1" {
		t.Fatalf("unexpected question: %s", dialog.Rounds[0].Query.Question)
	}

	bus.ResetDialog("case-001")
	dialog = bus.GetDialog("case-001")
	if dialog != nil && len(dialog.Rounds) != 0 {
		t.Fatal("expected empty dialog after reset")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/agentbus/ -v`
Expected: FAIL — New, Ask, AskForCase, etc. not defined

- [ ] **Step 3: Write the implementation**

```go
// internal/agentbus/bus.go
package agentbus

import (
	"context"
	"fmt"
	"sync"
)

type AgentHandler func(ctx context.Context, q Query) (Response, error)

type Bus struct {
	mu        sync.Mutex
	handlers  map[string]AgentHandler
	dialogs   map[string]*Dialog
	maxRounds int
}

func New(maxRounds int) *Bus {
	if maxRounds <= 0 {
		maxRounds = 3
	}
	return &Bus{
		handlers:  make(map[string]AgentHandler),
		dialogs:   make(map[string]*Dialog),
		maxRounds: maxRounds,
	}
}

func (b *Bus) Register(agentName string, handler AgentHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[agentName] = handler
}

func (b *Bus) Ask(ctx context.Context, q Query) (Response, error) {
	b.mu.Lock()
	handler, ok := b.handlers[q.ToAgent]
	b.mu.Unlock()
	if !ok {
		return Response{}, fmt.Errorf("unknown agent: %s", q.ToAgent)
	}
	return handler(ctx, q)
}

func (b *Bus) AskForCase(ctx context.Context, caseID string, q Query) (Response, error) {
	b.mu.Lock()
	dialog, exists := b.dialogs[caseID]
	if !exists {
		dialog = &Dialog{CaseID: caseID}
		b.dialogs[caseID] = dialog
	}
	if len(dialog.Rounds) >= b.maxRounds {
		b.mu.Unlock()
		return Response{}, fmt.Errorf("dialog round limit (%d) reached for case %s", b.maxRounds, caseID)
	}
	handler, ok := b.handlers[q.ToAgent]
	b.mu.Unlock()

	if !ok {
		return Response{}, fmt.Errorf("unknown agent: %s", q.ToAgent)
	}

	resp, err := handler(ctx, q)
	if err != nil {
		return Response{}, fmt.Errorf("agent %s: %w", q.ToAgent, err)
	}

	b.mu.Lock()
	dialog.Rounds = append(dialog.Rounds, Round{Query: q, Response: resp})
	b.mu.Unlock()

	return resp, nil
}

func (b *Bus) GetDialog(caseID string) *Dialog {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.dialogs[caseID]
	if !ok {
		return nil
	}
	return d
}

func (b *Bus) ResetDialog(caseID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.dialogs, caseID)
}

func (b *Bus) MaxRounds() int {
	return b.maxRounds
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/agentbus/ -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add internal/agentbus/
git commit -m "feat(agentbus): add Bus with routing, round limiting, and dialog tracking"
```

---

## Task 3: Handlers — LLM And Tool

**Files:**
- Create: `internal/agentbus/handlers.go`
- Create: `internal/agentbus/handlers_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/agentbus/handlers_test.go
package agentbus_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func TestNewLLMHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{
					"content": `{"answer":"The check is missing because verify_qe_identity_policy skips timestamp","facts":["verify.rs:42 no nonce"]}`,
				}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := llm.NewOpenAIClient(config.Config{
		LLMBaseURL:    srv.URL,
		LLMAPIKey:     "test-key",
		LLMModel:      "test-model",
		LLMTimeoutSec: 5,
		LLMTemp:       0.2,
	})

	handler := agentbus.NewLLMHandler(client, "You are the Expert Agent.", 0.2)
	resp, err := handler(context.Background(), agentbus.Query{
		QueryID:   "q-001",
		FromAgent: "verifier-001",
		ToAgent:   "expert-001",
		Kind:      "clarify",
		Question:  "Why is attestation missing?",
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.Answer == "" {
		t.Fatal("expected non-empty answer")
	}
	if len(resp.Facts) == 0 {
		t.Fatal("expected at least one fact")
	}
}

func TestNewToolHandler(t *testing.T) {
	handler := agentbus.NewToolHandler("mapper", func(_ context.Context, q agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "mapper",
			Answer:    "Found 3 matches",
			Facts:     []string{"verify.rs:10 fn verify_quote", "state.rs:20 fn apply"},
		}, nil
	})

	resp, err := handler(context.Background(), agentbus.Query{
		QueryID:  "q-001",
		ToAgent:  "mapper",
		Kind:     "search",
		Question: "Find verify-related code",
	})
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if resp.FromAgent != "mapper" {
		t.Fatalf("expected from mapper, got %s", resp.FromAgent)
	}
	if len(resp.Facts) != 2 {
		t.Fatalf("expected 2 facts, got %d", len(resp.Facts))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/agentbus/ -v`
Expected: FAIL — NewLLMHandler, NewToolHandler not defined

- [ ] **Step 3: Write the implementation**

```go
// internal/agentbus/handlers.go
package agentbus

import (
	"context"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func NewLLMHandler(client llm.Client, systemPrompt string, temperature float64) AgentHandler {
	return func(ctx context.Context, q Query) (Response, error) {
		userMsg := fmt.Sprintf("Agent %s asks (%s):\n%s", q.FromAgent, q.Kind, q.Question)
		if q.Context != nil {
			userMsg += fmt.Sprintf("\n\nAdditional context: %v", q.Context)
		}

		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt + "\n\nReturn a JSON object with fields: answer (string), facts (array of strings).",
			Messages: []llm.Message{
				{Role: "user", Content: userMsg},
			},
			Temperature: temperature,
		})
		if err != nil {
			return Response{}, fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			Answer string   `json:"answer"`
			Facts  []string `json:"facts"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return Response{
				QueryID:   q.QueryID,
				FromAgent: q.ToAgent,
				Answer:    resp.Text,
			}, nil
		}

		return Response{
			QueryID:   q.QueryID,
			FromAgent: q.ToAgent,
			Answer:    parsed.Answer,
			Facts:     parsed.Facts,
		}, nil
	}
}

func NewToolHandler(name string, fn func(ctx context.Context, q Query) (Response, error)) AgentHandler {
	return func(ctx context.Context, q Query) (Response, error) {
		return fn(ctx, q)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/agentbus/ -v`
Expected: PASS (6 tests total)

- [ ] **Step 5: Commit**

```bash
git add internal/agentbus/handlers.go internal/agentbus/handlers_test.go
git commit -m "feat(agentbus): add LLM and tool handler builders"
```

---

## Task 4: Live LLM Data Source Test

**Files:**
- Create: `internal/llm/live_test.go`

This test validates real LLM connectivity. It is skipped unless `TEECHECK_LLM_API_KEY` is set.

- [ ] **Step 1: Write the test**

```go
// internal/llm/live_test.go
package llm_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

func TestLiveLLMDataSource(t *testing.T) {
	apiKey := os.Getenv("TEECHECK_LLM_API_KEY")
	if apiKey == "" {
		t.Skip("TEECHECK_LLM_API_KEY not set, skipping live LLM test")
	}
	baseURL := os.Getenv("TEECHECK_LLM_BASE_URL")
	if baseURL == "" {
		t.Skip("TEECHECK_LLM_BASE_URL not set, skipping live LLM test")
	}
	model := os.Getenv("TEECHECK_LLM_MODEL")
	if model == "" {
		t.Skip("TEECHECK_LLM_MODEL not set, skipping live LLM test")
	}

	client := llm.NewOpenAIClient(config.Config{
		LLMBaseURL:    baseURL,
		LLMAPIKey:     apiKey,
		LLMModel:      model,
		LLMTimeoutSec: 30,
		LLMTemp:       0.1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: Basic connectivity — can we get a response?
	t.Run("BasicConnectivity", func(t *testing.T) {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: "You are a helpful assistant. Respond with exactly one word.",
			Messages: []llm.Message{
				{Role: "user", Content: "Say hello."},
			},
			Temperature: 0.0,
		})
		if err != nil {
			t.Fatalf("LLM request failed: %v", err)
		}
		if resp.Text == "" {
			t.Fatal("LLM returned empty response")
		}
		t.Logf("Basic connectivity OK, response: %q", resp.Text)
	})

	// Test 2: JSON output — can it return structured data?
	t.Run("JSONOutput", func(t *testing.T) {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: "You are a JSON generator. Return exactly one JSON object, no other text.",
			Messages: []llm.Message{
				{Role: "user", Content: `Return a JSON object with fields: answer (string), facts (array of strings). Topic: "why is code review important?"`},
			},
			Temperature: 0.0,
		})
		if err != nil {
			t.Fatalf("LLM request failed: %v", err)
		}

		// Try to parse as JSON
		text := strings.TrimSpace(resp.Text)
		var parsed struct {
			Answer string   `json:"answer"`
			Facts  []string `json:"facts"`
		}
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			// Try extracting JSON from markdown code block
			if idx := strings.Index(text, "{"); idx >= 0 {
				if end := strings.LastIndex(text, "}"); end > idx {
					text = text[idx : end+1]
					err = json.Unmarshal([]byte(text), &parsed)
				}
			}
			if err != nil {
				t.Fatalf("LLM response is not valid JSON: %v\nRaw: %s", err, resp.Text)
			}
		}
		if parsed.Answer == "" {
			t.Fatal("LLM returned empty answer field")
		}
		t.Logf("JSON output OK, answer: %q, facts: %v", parsed.Answer, parsed.Facts)
	})

	// Test 3: Agent-style prompt — simulates a real TEECheck agent query
	t.Run("AgentStyleQuery", func(t *testing.T) {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: `You are the Expert Agent in TEECheck. Another agent asks you a question about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).`,
			Messages: []llm.Message{
				{Role: "user", Content: `Agent verifier-001 asks (clarify):
Why do you suspect the attestation check is incomplete?

Additional context: The function verify_qe_identity_policy in verify.rs does not appear to validate a timestamp or nonce.`},
			},
			Temperature: 0.2,
		})
		if err != nil {
			t.Fatalf("LLM request failed: %v", err)
		}

		var parsed struct {
			Answer string   `json:"answer"`
			Facts  []string `json:"facts"`
		}
		text := resp.Text
		if idx := strings.Index(text, "{"); idx >= 0 {
			if end := strings.LastIndex(text, "}"); end > idx {
				text = text[idx : end+1]
			}
		}
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatalf("Failed to parse agent response as JSON: %v\nRaw: %s", err, resp.Text)
		}
		if parsed.Answer == "" {
			t.Fatal("Agent returned empty answer")
		}
		t.Logf("Agent query OK, answer length: %d chars, facts: %d", len(parsed.Answer), len(parsed.Facts))
	})
}
```

- [ ] **Step 2: Run test (expect skip without env vars)**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/llm/ -v -run TestLiveLLMDataSource`
Expected: SKIP — "TEECHECK_LLM_API_KEY not set, skipping live LLM test"

- [ ] **Step 3: Commit**

```bash
git add internal/llm/live_test.go
git commit -m "test(llm): add live data source connectivity test (skipped without API key)"
```

The user will provide the API key. Then run:

```bash
TEECHECK_LLM_API_KEY=<key> TEECHECK_LLM_BASE_URL=<url> TEECHECK_LLM_MODEL=<model> \
  go test ./internal/llm/ -v -run TestLiveLLMDataSource
```

---

## Task 5: Config Changes — ArbiterMode, CuratorMode, MaxDialogRounds

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/runfs/paths.go`

- [ ] **Step 1: Add fields to Config struct**

In `internal/config/config.go`, add after `StaticTools string`:

```go
ArbiterMode     string
CuratorMode     string
MaxDialogRounds int
```

- [ ] **Step 2: Add flags to parseCollabRun**

Add to the cfg literal defaults:

```go
ArbiterMode:     "heuristic",
CuratorMode:     "heuristic",
MaxDialogRounds: 3,
```

Add flags:

```go
fs.StringVar(&cfg.ArbiterMode, "arbiter-mode", cfg.ArbiterMode, "Arbiter mode: heuristic or llm")
fs.StringVar(&cfg.CuratorMode, "curator-mode", cfg.CuratorMode, "Curator mode: heuristic or llm")
fs.IntVar(&cfg.MaxDialogRounds, "max-dialog-rounds", cfg.MaxDialogRounds, "Maximum inter-agent dialog rounds per case")
```

- [ ] **Step 3: Add --mode flag to parseArbiter**

Add to cfg defaults: `ArbiterMode: "heuristic"`, plus LLM env defaults (same as other agents).
Add flag:

```go
fs.StringVar(&cfg.ArbiterMode, "mode", cfg.ArbiterMode, "Arbiter mode: heuristic or llm")
```

Add LLM flags (same as parseExpert pattern). Add `validateAgentLLM(cfg.ArbiterMode, cfg, "arbiter")` check.

- [ ] **Step 4: Add parseCurator function**

```go
func parseCurator(args []string) (Config, error) {
	fs := flag.NewFlagSet("curator", flag.ContinueOnError)
	cfg := Config{
		Command:         "curator",
		AgentID:         "curator-001",
		CuratorMode:     "heuristic",
		KnowledgeRoot:   filepath.Clean("knowledge"),
		MaxDialogRounds: 3,
		LLMProvider:     firstNonEmptyEnv("TEECHECK_LLM_PROVIDER", "OPENAI_PROVIDER"),
		LLMBaseURL:      firstNonEmptyEnv("TEECHECK_LLM_BASE_URL", "OPENAI_BASE_URL"),
		LLMAPIKey:       firstNonEmptyEnv("TEECHECK_LLM_API_KEY", "OPENAI_API_KEY"),
		LLMModel:        firstNonEmptyEnv("TEECHECK_LLM_MODEL", "OPENAI_MODEL"),
		LLMTimeoutSec:   envInt(60, "TEECHECK_LLM_TIMEOUT_SECONDS"),
		LLMTemp:         envFloat(0.2, "TEECHECK_LLM_TEMPERATURE"),
	}
	fs.StringVar(&cfg.RunDir, "run-dir", "", "Run directory containing review outputs")
	fs.StringVar(&cfg.KnowledgeRoot, "knowledge-root", cfg.KnowledgeRoot, "Knowledge root directory")
	fs.StringVar(&cfg.AgentID, "agent-id", cfg.AgentID, "Stable curator agent identifier")
	fs.StringVar(&cfg.CuratorMode, "mode", cfg.CuratorMode, "Curator mode: heuristic or llm")
	fs.IntVar(&cfg.MaxDialogRounds, "max-dialog-rounds", cfg.MaxDialogRounds, "Maximum inter-agent dialog rounds per case")
	fs.StringVar(&cfg.LLMProvider, "llm-provider", cfg.LLMProvider, "LLM provider")
	fs.StringVar(&cfg.LLMBaseURL, "llm-base-url", cfg.LLMBaseURL, "OpenAI-compatible base URL")
	fs.StringVar(&cfg.LLMAPIKey, "llm-api-key", cfg.LLMAPIKey, "OpenAI-compatible API key")
	fs.StringVar(&cfg.LLMModel, "llm-model", cfg.LLMModel, "Model name")
	fs.IntVar(&cfg.LLMTimeoutSec, "llm-timeout-seconds", cfg.LLMTimeoutSec, "HTTP timeout in seconds")
	fs.Float64Var(&cfg.LLMTemp, "llm-temperature", cfg.LLMTemp, "Sampling temperature")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.RunDir == "" {
		return Config{}, fmt.Errorf("curator requires --run-dir")
	}
	if err := validateAgentLLM(cfg.CuratorMode, cfg, "curator"); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
```

- [ ] **Step 5: Add routing in Parse switch**

Add:

```go
case "curator":
	return parseCurator(args[1:])
```

Keep existing `"feedback"` case pointing to `parseFeedback` for backward compat.

- [ ] **Step 6: Update validateLLMIfNeeded to include new modes**

```go
func validateLLMIfNeeded(cfg Config, context string) error {
	if normalizeMode(cfg.ExpertMode) != "llm" &&
		normalizeMode(cfg.ChallengeMode) != "llm" &&
		normalizeMode(cfg.VerifierMode) != "llm" &&
		normalizeMode(cfg.ArbiterMode) != "llm" &&
		normalizeMode(cfg.CuratorMode) != "llm" {
		return nil
	}
	return validateProviderConfig(cfg, context)
}
```

- [ ] **Step 7: Add CuratorDir to runfs/paths.go**

Append after `ReviewRecordsPath`:

```go
func CuratorDir(runDir string) string {
	return filepath.Join(runDir, "09_curator")
}
```

- [ ] **Step 8: Update usageError string**

Add:

```
  teecheck curator --run-dir DIR [--knowledge-root DIR] [--mode heuristic|llm] [--max-dialog-rounds N]
```

- [ ] **Step 9: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/config/ ./internal/runfs/`
Expected: no errors

- [ ] **Step 10: Commit**

```bash
git add internal/config/config.go internal/runfs/paths.go
git commit -m "feat(config): add ArbiterMode, CuratorMode, MaxDialogRounds and curator subcommand"
```

---

## Task 6: Verifier LLM Mode

**Files:**
- Modify: `internal/verifier/run.go`

- [ ] **Step 1: Add RunWithBus function**

Add after the existing `Run` function. The existing `Run` stays unchanged for heuristic mode.

```go
func RunWithBus(cfg config.Config, bus *agentbus.Bus) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	client := llm.NewClient(cfg)

	reg := scall.NewDefaultRegistry()
	enabledTools := parseStaticTools(cfg.StaticTools)

	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", casePath, err)
		}
		var hypothesis artifacts.Hypothesis
		if err := runfs.ReadJSON(filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1)), &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis: %w", err)
		}
		var challenge artifacts.Challenge
		if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1)), &challenge); err != nil {
			return fmt.Errorf("read challenge: %w", err)
		}

		// Run static checks
		var scFindings []staticcheck.CheckFinding
		if enabledTools != nil {
			req := staticcheck.CheckRequest{
				RepoRoot:    manifest.LocalPath,
				TargetFiles: pack.TargetFiles,
				Keywords:    append(pack.ExpectedObligations, pack.TargetSymbols...),
				Category:    pack.Category,
			}
			for _, toolName := range enabledTools {
				results, err := reg.RunByName(context.Background(), toolName, req)
				if err != nil {
					fmt.Printf("Warning: static check %s failed: %v\n", toolName, err)
					continue
				}
				scFindings = append(scFindings, results...)
			}
		}

		bus.ResetDialog(pack.CaseID)
		memo, err := buildMemoLLM(context.Background(), client, bus, pack, hypothesis, challenge, cfg.AgentID, cfg.LLMTemp, scFindings)
		if err != nil {
			return fmt.Errorf("verifier llm for %s: %w", pack.CaseID, err)
		}

		target := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, memo); err != nil {
			return fmt.Errorf("write verification memo: %w", err)
		}

		// Save dialog
		if dialog := bus.GetDialog(pack.CaseID); dialog != nil && len(dialog.Rounds) > 0 {
			dialogPath := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("dialog-%03d.jsonl", idx+1))
			if err := writeDialogJSONL(dialogPath, dialog); err != nil {
				fmt.Printf("Warning: failed to write dialog: %v\n", err)
			}
		}
		count++
	}
	fmt.Printf("Wrote %d verification memo(s) to %s\n", count, runfs.VerifierDir(cfg.RunDir))
	return nil
}

func buildMemoLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, agentID string, temperature float64, scFindings []staticcheck.CheckFinding) (artifacts.VerificationMemo, error) {
	systemPrompt := `You are the Verifier Agent in TEECheck. Analyze static check results and code evidence to arbitrate between the Expert's hypothesis and the Challenger's objections.

Return a JSON object with fields:
- status: "corroborated" | "contested" | "inconclusive"
- checks_run: array of strings
- confirmed_facts: array of strings
- contradictions: array of strings
- notes: array of strings
- queries: array of objects (optional, each with: to_agent, kind, question) — if you need more information from other agents`

	userMsg := fmt.Sprintf(`Case: %s (category: %s, priority: %s)
Target files: %s
Target symbols: %s

Expert hypothesis:
- Title: %s
- Suspected issue: %s
- Missing obligations: %s
- Supporting facts: %s
- Confidence: %s

Challenger view:
- Exploitability: %s
- Narrative: %s
- Counter arguments: %s
- Remaining questions: %s

Static check findings (%d total):
%s`,
		pack.CaseID, pack.Category, pack.Priority,
		strings.Join(pack.TargetFiles, ", "),
		strings.Join(pack.TargetSymbols, ", "),
		hypothesis.Title, hypothesis.SuspectedIssue,
		strings.Join(hypothesis.MissingObligations, ", "),
		strings.Join(hypothesis.SupportingFacts, " | "),
		hypothesis.Confidence,
		challenge.Exploitability, challenge.ExploitNarrative,
		strings.Join(challenge.CounterArguments, " | "),
		strings.Join(challenge.RemainingQuestions, " | "),
		len(scFindings), formatCheckFindings(scFindings))

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
		})
		if err != nil {
			return artifacts.VerificationMemo{}, fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			Status         string   `json:"status"`
			ChecksRun      []string `json:"checks_run"`
			ConfirmedFacts []string `json:"confirmed_facts"`
			Contradictions []string `json:"contradictions"`
			Notes          []string `json:"notes"`
			Queries        []struct {
				ToAgent  string `json:"to_agent"`
				Kind     string `json:"kind"`
				Question string `json:"question"`
			} `json:"queries"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return artifacts.VerificationMemo{}, fmt.Errorf("parse verifier json: %w | raw=%s", err, truncate(resp.Text, 400))
		}

		// If no queries, we have our final answer
		if len(parsed.Queries) == 0 {
			return artifacts.VerificationMemo{
				SchemaVersion:  "teecheck.verification_memo.v1",
				CaseID:         pack.CaseID,
				AgentID:        agentID,
				Status:         normalizeStatus(parsed.Status),
				ChecksRun:      parsed.ChecksRun,
				ConfirmedFacts: parsed.ConfirmedFacts,
				Contradictions: parsed.Contradictions,
				Notes:          parsed.Notes,
			}, nil
		}

		// Process queries via bus
		var queryResults []string
		for i, q := range parsed.Queries {
			busResp, err := bus.AskForCase(ctx, pack.CaseID, agentbus.Query{
				QueryID:   fmt.Sprintf("verifier-%s-r%d-q%d", pack.CaseID, round, i),
				FromAgent: agentID,
				ToAgent:   q.ToAgent,
				Kind:      q.Kind,
				Question:  q.Question,
			})
			if err != nil {
				queryResults = append(queryResults, fmt.Sprintf("Query to %s failed: %v", q.ToAgent, err))
				continue
			}
			queryResults = append(queryResults, fmt.Sprintf("Response from %s: %s\nFacts: %s", busResp.FromAgent, busResp.Answer, strings.Join(busResp.Facts, "; ")))
		}

		// Append query results and loop
		followUp := fmt.Sprintf("Here are the responses to your queries:\n%s\n\nNow provide your final judgment with the same JSON format. If you still need information, include more queries.", strings.Join(queryResults, "\n\n"))
		messages = append(messages, llm.Message{Role: "assistant", Content: resp.Text})
		messages = append(messages, llm.Message{Role: "user", Content: followUp})
	}

	return artifacts.VerificationMemo{
		SchemaVersion: "teecheck.verification_memo.v1",
		CaseID:        pack.CaseID,
		AgentID:       agentID,
		Status:        "inconclusive",
		Notes:         []string{"Reached maximum dialog rounds without final judgment"},
	}, nil
}

func formatCheckFindings(findings []staticcheck.CheckFinding) string {
	if len(findings) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("  - [%s] %s:%d %s (severity: %s)", f.ToolName, f.Path, f.StartLine, f.Message, f.Severity))
	}
	return strings.Join(lines, "\n")
}

func normalizeStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "corroborated":
		return "corroborated"
	case "contested":
		return "contested"
	default:
		return "inconclusive"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func writeDialogJSONL(path string, dialog *agentbus.Dialog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, round := range dialog.Rounds {
		if err := enc.Encode(round); err != nil {
			return err
		}
	}
	return nil
}
```

Add imports: `"encoding/json"`, `"os"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"`.

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/verifier/`
Expected: no errors

- [ ] **Step 3: Run existing tests**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./internal/collabrun/ -v`
Expected: PASS (heuristic path unaffected)

- [ ] **Step 4: Commit**

```bash
git add internal/verifier/run.go
git commit -m "feat(verifier): add LLM mode with inter-agent dialog via bus"
```

---

## Task 7: Arbiter LLM Mode

**Files:**
- Modify: `internal/arbiter/run.go`

- [ ] **Step 1: Add RunWithBus function**

Add after existing `Run` function. Same pattern as verifier: existing `Run` untouched.

```go
func RunWithBus(cfg config.Config, bus *agentbus.Bus) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	_ = manifest // used for context in future

	client := llm.NewClient(cfg)

	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         manifest.RunID,
	}
	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack: %w", err)
		}
		var hypothesis artifacts.Hypothesis
		if err := runfs.ReadJSON(filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1)), &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis: %w", err)
		}
		var challenge artifacts.Challenge
		if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1)), &challenge); err != nil {
			return fmt.Errorf("read challenge: %w", err)
		}
		var memo artifacts.VerificationMemo
		if err := runfs.ReadJSON(filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1)), &memo); err != nil {
			return fmt.Errorf("read verification memo: %w", err)
		}

		bus.ResetDialog(pack.CaseID)
		item, packet, err := arbitrateLLM(context.Background(), client, bus, pack, hypothesis, challenge, memo, cfg.AgentID, cfg.LLMTemp)
		if err != nil {
			return fmt.Errorf("arbiter llm for %s: %w", pack.CaseID, err)
		}

		if cfg.MaxFindings == 0 || len(findings.Findings) < cfg.MaxFindings {
			findings.Findings = append(findings.Findings, item)
		}
		packetPath := filepath.Join(runfs.ArbiterPacketsDir(cfg.RunDir), fmt.Sprintf("review-%03d.md", idx+1))
		if err := runfs.WriteText(packetPath, packet); err != nil {
			return fmt.Errorf("write arbiter packet: %w", err)
		}

		if dialog := bus.GetDialog(pack.CaseID); dialog != nil && len(dialog.Rounds) > 0 {
			dialogPath := filepath.Join(runfs.ArbiterDir(cfg.RunDir), fmt.Sprintf("dialog-%03d.jsonl", idx+1))
			if err := writeDialogJSONL(dialogPath, dialog); err != nil {
				fmt.Printf("Warning: failed to write arbiter dialog: %v\n", err)
			}
		}
		count++
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(cfg.RunDir), findings); err != nil {
		return fmt.Errorf("write arbiter findings: %w", err)
	}
	fmt.Printf("Wrote %d arbiter packet(s) to %s\n", count, runfs.ArbiterDir(cfg.RunDir))
	return nil
}

func arbitrateLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo, agentID string, temperature float64) (artifacts.FindingItem, string, error) {
	systemPrompt := `You are the Arbiter Agent in TEECheck. Synthesize all evidence and produce a final judgment and human-readable review packet.

Return a JSON object with fields:
- status: "no_issue_observed" | "needs_review" | "likely_issue" | "confirmed_candidate"
- severity: "high" | "medium" | "low"
- confidence: "high" | "medium" | "low"
- summary: string
- evidence: array of strings
- review_packet_markdown: string (full review packet in markdown)
- queries: array of objects (optional, each with: to_agent, kind, question)`

	userMsg := fmt.Sprintf(`Case: %s (category: %s, priority: %s)
Files: %s

Expert hypothesis:
- Title: %s
- Suspected issue: %s
- Confidence: %s
- Supporting facts: %s

Challenger view:
- Exploitability: %s
- Stance: %s
- Counter arguments: %s

Verification:
- Status: %s
- Confirmed facts: %s
- Contradictions: %s

Knowledge hints:
%s`,
		pack.CaseID, pack.Category, pack.Priority,
		strings.Join(pack.TargetFiles, ", "),
		hypothesis.Title, hypothesis.SuspectedIssue, hypothesis.Confidence,
		strings.Join(hypothesis.SupportingFacts, " | "),
		challenge.Exploitability, challenge.ReviewerStance,
		strings.Join(challenge.CounterArguments, " | "),
		memo.Status,
		strings.Join(memo.ConfirmedFacts, " | "),
		strings.Join(memo.Contradictions, " | "),
		formatKnowledgeHints(pack.KnowledgeHints))

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
		})
		if err != nil {
			return artifacts.FindingItem{}, "", fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			Status              string   `json:"status"`
			Severity            string   `json:"severity"`
			Confidence          string   `json:"confidence"`
			Summary             string   `json:"summary"`
			Evidence            []string `json:"evidence"`
			ReviewPacketMarkdown string  `json:"review_packet_markdown"`
			Queries             []struct {
				ToAgent  string `json:"to_agent"`
				Kind     string `json:"kind"`
				Question string `json:"question"`
			} `json:"queries"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return artifacts.FindingItem{}, "", fmt.Errorf("parse arbiter json: %w | raw=%s", err, truncate(resp.Text, 400))
		}

		if len(parsed.Queries) == 0 {
			item := artifacts.FindingItem{
				FindingID:  pack.CaseID,
				SliceID:    pack.CaseID,
				Status:     parsed.Status,
				Severity:   parsed.Severity,
				Confidence: parsed.Confidence,
				Files:      pack.TargetFiles,
				Summary:    parsed.Summary,
				Evidence:   parsed.Evidence,
			}
			packet := parsed.ReviewPacketMarkdown
			if packet == "" {
				packet = buildPacket(pack, hypothesis, challenge, memo, item)
			}
			return item, packet, nil
		}

		var queryResults []string
		for i, q := range parsed.Queries {
			busResp, err := bus.AskForCase(ctx, pack.CaseID, agentbus.Query{
				QueryID:   fmt.Sprintf("arbiter-%s-r%d-q%d", pack.CaseID, round, i),
				FromAgent: agentID,
				ToAgent:   q.ToAgent,
				Kind:      q.Kind,
				Question:  q.Question,
			})
			if err != nil {
				queryResults = append(queryResults, fmt.Sprintf("Query to %s failed: %v", q.ToAgent, err))
				continue
			}
			queryResults = append(queryResults, fmt.Sprintf("Response from %s: %s\nFacts: %s", busResp.FromAgent, busResp.Answer, strings.Join(busResp.Facts, "; ")))
		}

		followUp := fmt.Sprintf("Here are the responses to your queries:\n%s\n\nNow provide your final judgment.", strings.Join(queryResults, "\n\n"))
		messages = append(messages, llm.Message{Role: "assistant", Content: resp.Text})
		messages = append(messages, llm.Message{Role: "user", Content: followUp})
	}

	item := artifacts.FindingItem{
		FindingID:  pack.CaseID,
		SliceID:    pack.CaseID,
		Status:     "needs_review",
		Severity:   severityForCategory(pack.Category),
		Confidence: "low",
		Files:      pack.TargetFiles,
		Summary:    "Reached maximum dialog rounds without final arbiter judgment",
	}
	return item, buildPacket(pack, hypothesis, challenge, memo, item), nil
}

func formatKnowledgeHints(hints []artifacts.KnowledgeHint) string {
	if len(hints) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, h := range hints {
		lines = append(lines, fmt.Sprintf("  - %s: %s", h.Title, h.Reason))
	}
	return strings.Join(lines, "\n")
}

func writeDialogJSONL(path string, dialog *agentbus.Dialog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, round := range dialog.Rounds {
		if err := enc.Encode(round); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
```

Add imports: `"context"`, `"encoding/json"`, `"os"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"`.

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/arbiter/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/arbiter/run.go
git commit -m "feat(arbiter): add LLM mode with inter-agent dialog via bus"
```

---

## Task 8: Curator LLM Mode (Feedback)

**Files:**
- Modify: `internal/feedback/run.go`

- [ ] **Step 1: Add RunWithBus function**

Add after existing `Run` function:

```go
func RunWithBus(cfg config.Config, w io.Writer, bus *agentbus.Bus) error {
	records, err := loadReviewRecords(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load review records: %w", err)
	}
	if len(records) == 0 {
		fmt.Fprintln(w, "No review records found.")
		return nil
	}

	var findings artifacts.Findings
	findingsMap := make(map[string]artifacts.FindingItem)
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err == nil {
		for _, f := range findings.Findings {
			findingsMap[f.FindingID] = f
		}
	}

	client := llm.NewClient(cfg)

	// Load wiki page summaries (titles and tags only, to save tokens)
	pages, _ := knowledge.LoadPages(cfg.KnowledgeRoot)
	pageSummary := formatPageSummaries(pages)

	archived := 0
	for idx, rec := range records {
		finding := findingsMap[rec.FindingID]

		bus.ResetDialog(rec.CaseID)
		result, err := curateLLM(context.Background(), client, bus, rec, finding, pageSummary, cfg.AgentID, cfg.LLMTemp)
		if err != nil {
			fmt.Fprintf(w, "Warning: curator LLM failed for %s: %v, falling back to heuristic\n", rec.CaseID, err)
			archiveFinding(cfg.KnowledgeRoot, verdictToCategory(rec.Verdict), rec, &finding)
			archived++
			continue
		}

		// Write archive content from LLM
		category := verdictToCategory(rec.Verdict)
		archiveDir := filepath.Join(cfg.KnowledgeRoot, "learned", category)
		if err := os.MkdirAll(archiveDir, 0o755); err != nil {
			return err
		}
		archivePath := filepath.Join(archiveDir, sanitizeFilename(rec.FindingID)+".md")
		if err := os.WriteFile(archivePath, []byte(result.ArchiveContent), 0o644); err != nil {
			return fmt.Errorf("write archive: %w", err)
		}
		archived++

		// Apply wiki updates
		for _, update := range result.WikiUpdates {
			if update.Action == "append" {
				fullPath := filepath.Join(cfg.KnowledgeRoot, update.PagePath)
				f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_APPEND, 0o644)
				if err != nil {
					fmt.Fprintf(w, "Warning: could not append to %s: %v\n", update.PagePath, err)
					continue
				}
				f.WriteString("\n" + update.Content + "\n")
				f.Close()
				fmt.Fprintf(w, "Appended to %s: %s\n", update.PagePath, update.Reason)
			} else {
				fmt.Fprintf(w, "Suggest new wiki page: %s — %s\n", update.PagePath, update.Reason)
			}
		}

		// Save dialog
		if dialog := bus.GetDialog(rec.CaseID); dialog != nil && len(dialog.Rounds) > 0 {
			dialogPath := filepath.Join(runfs.CuratorDir(cfg.RunDir), fmt.Sprintf("dialog-%03d.jsonl", idx+1))
			if err := writeDialogJSONL(dialogPath, dialog); err != nil {
				fmt.Fprintf(w, "Warning: failed to write curator dialog: %v\n", err)
			}
		}
	}

	fmt.Fprintf(w, "\nArchived %d review record(s) to %s/learned/\n", archived, cfg.KnowledgeRoot)
	return nil
}

type curatorResult struct {
	ArchiveContent string
	WikiUpdates    []wikiUpdate
}

type wikiUpdate struct {
	Action   string `json:"action"`
	PagePath string `json:"page_path"`
	Content  string `json:"content"`
	Reason   string `json:"reason"`
}

func curateLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, rec artifacts.ReviewRecord, finding artifacts.FindingItem, pageSummary string, agentID string, temperature float64) (curatorResult, error) {
	systemPrompt := `You are the Curator Agent in TEECheck. Your role is to maintain the knowledge base from human review outcomes. You can ask other agents about their reasoning.

Return a JSON object with fields:
- archive_content: string (markdown for the learned/ archive page)
- wiki_updates: array of objects, each with: action ("append"|"suggest_new"), page_path (string), content (string), reason (string)
- queries: array of objects (optional, each with: to_agent, kind, question)`

	userMsg := fmt.Sprintf(`Review record:
- Case: %s
- Verdict: %s
- Severity: %s
- Tags: %s
- Notes: %s
- Reviewed at: %s

Finding context:
- Summary: %s
- Status: %s
- Files: %s
- Evidence: %s

Existing wiki pages:
%s`,
		rec.CaseID, rec.Verdict, rec.Severity,
		strings.Join(rec.Tags, ", "), rec.Notes, rec.ReviewedAt,
		finding.Summary, finding.Status,
		strings.Join(finding.Files, ", "),
		strings.Join(finding.Evidence, " | "),
		pageSummary)

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
		})
		if err != nil {
			return curatorResult{}, fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			ArchiveContent string       `json:"archive_content"`
			WikiUpdates    []wikiUpdate `json:"wiki_updates"`
			Queries        []struct {
				ToAgent  string `json:"to_agent"`
				Kind     string `json:"kind"`
				Question string `json:"question"`
			} `json:"queries"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return curatorResult{}, fmt.Errorf("parse curator json: %w | raw=%s", err, truncate(resp.Text, 400))
		}

		if len(parsed.Queries) == 0 {
			return curatorResult{
				ArchiveContent: parsed.ArchiveContent,
				WikiUpdates:    parsed.WikiUpdates,
			}, nil
		}

		var queryResults []string
		for i, q := range parsed.Queries {
			busResp, err := bus.AskForCase(ctx, rec.CaseID, agentbus.Query{
				QueryID:   fmt.Sprintf("curator-%s-r%d-q%d", rec.CaseID, round, i),
				FromAgent: agentID,
				ToAgent:   q.ToAgent,
				Kind:      q.Kind,
				Question:  q.Question,
			})
			if err != nil {
				queryResults = append(queryResults, fmt.Sprintf("Query to %s failed: %v", q.ToAgent, err))
				continue
			}
			queryResults = append(queryResults, fmt.Sprintf("Response from %s: %s", busResp.FromAgent, busResp.Answer))
		}

		followUp := fmt.Sprintf("Here are the responses:\n%s\n\nNow provide your final output.", strings.Join(queryResults, "\n\n"))
		messages = append(messages, llm.Message{Role: "assistant", Content: resp.Text})
		messages = append(messages, llm.Message{Role: "user", Content: followUp})
	}

	return curatorResult{}, fmt.Errorf("reached maximum dialog rounds without curator output")
}

func formatPageSummaries(pages []knowledge.Page) string {
	if len(pages) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, p := range pages {
		lines = append(lines, fmt.Sprintf("  - %s [%s] tags: %s", p.Title, p.Path, strings.Join(p.Tags, ",")))
	}
	return strings.Join(lines, "\n")
}

func verdictToCategory(verdict string) string {
	switch verdict {
	case "confirmed", "confirmed_via_patch":
		return "true-positive"
	case "dismissed", "false_alarm":
		return "false-positive"
	default:
		return "review-memory"
	}
}

func sanitizeFilename(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "@", "_")
	return r.Replace(s)
}

func writeDialogJSONL(path string, dialog *agentbus.Dialog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, round := range dialog.Rounds {
		if err := enc.Encode(round); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
```

Add imports: `"context"`, `"strings"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"`.

- [ ] **Step 2: Verify it compiles**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./internal/feedback/`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add internal/feedback/run.go
git commit -m "feat(curator): add LLM mode with inter-agent dialog via bus"
```

---

## Task 9: Orchestrator — Wire Bus Into collabrun And main.go

**Files:**
- Modify: `internal/collabrun/run.go`
- Modify: `cmd/teecheck/main.go`

- [ ] **Step 1: Update collabrun/run.go**

Replace the current content with:

```go
package collabrun

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/arbiter"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/cases"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/challenger"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/expert"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/knowledge"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/preprocessor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runinit"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/verifier"
)

func Run(cfg config.Config, now time.Time) (string, error) {
	if err := knowledge.EnsureLayout(cfg.KnowledgeRoot); err != nil {
		return "", fmt.Errorf("ensure knowledge layout: %w", err)
	}
	initCfg := cfg
	initCfg.Command = "init-run"
	runDir, err := runinit.Run(initCfg, now)
	if err != nil {
		return "", err
	}

	stageCfg := cfg
	stageCfg.RunDir = runDir

	if err := preprocessor.Run(stageCfg); err != nil {
		return "", fmt.Errorf("preprocess: %w", err)
	}
	if err := mapper.Run(stageCfg); err != nil {
		return "", fmt.Errorf("mapper: %w", err)
	}
	if err := cases.Run(stageCfg); err != nil {
		return "", fmt.Errorf("cases: %w", err)
	}

	stageCfg.AgentID = "expert-001"
	if err := expert.Run(stageCfg); err != nil {
		return "", fmt.Errorf("expert: %w", err)
	}

	stageCfg.AgentID = "challenger-001"
	if err := challenger.Run(stageCfg); err != nil {
		return "", fmt.Errorf("challenger: %w", err)
	}

	// Determine if any downstream agent needs the bus
	needsBus := anyLLMMode(cfg.VerifierMode, cfg.ArbiterMode)

	if needsBus {
		bus := buildBus(cfg)

		stageCfg.AgentID = "verifier-001"
		if strings.EqualFold(cfg.VerifierMode, "llm") {
			if err := verifier.RunWithBus(stageCfg, bus); err != nil {
				return "", fmt.Errorf("verifier: %w", err)
			}
		} else {
			if err := verifier.Run(stageCfg); err != nil {
				return "", fmt.Errorf("verifier: %w", err)
			}
		}

		stageCfg.AgentID = "arbiter-001"
		if strings.EqualFold(cfg.ArbiterMode, "llm") {
			if err := arbiter.RunWithBus(stageCfg, bus); err != nil {
				return "", fmt.Errorf("arbiter: %w", err)
			}
		} else {
			if err := arbiter.Run(stageCfg); err != nil {
				return "", fmt.Errorf("arbiter: %w", err)
			}
		}
	} else {
		stageCfg.AgentID = "verifier-001"
		if err := verifier.Run(stageCfg); err != nil {
			return "", fmt.Errorf("verifier: %w", err)
		}

		stageCfg.AgentID = "arbiter-001"
		if err := arbiter.Run(stageCfg); err != nil {
			return "", fmt.Errorf("arbiter: %w", err)
		}
	}

	return runDir, nil
}

func anyLLMMode(modes ...string) bool {
	for _, m := range modes {
		if strings.EqualFold(m, "llm") {
			return true
		}
	}
	return false
}

func buildBus(cfg config.Config) *agentbus.Bus {
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)

	// Register LLM handlers for agents that may receive queries
	var client llm.Client
	if anyLLMMode(cfg.VerifierMode, cfg.ArbiterMode, cfg.CuratorMode) {
		client = llm.NewClient(cfg)
	}

	if client != nil {
		bus.Register("expert-001", agentbus.NewLLMHandler(client,
			"You are the Expert Agent in TEECheck. Another agent asks you about your security analysis. Return a JSON object with fields: answer (string), facts (array of strings).",
			cfg.LLMTemp))
		bus.Register("challenger-001", agentbus.NewLLMHandler(client,
			"You are the Challenger Agent in TEECheck. Another agent asks you about your challenge. Return a JSON object with fields: answer (string), facts (array of strings).",
			cfg.LLMTemp))
		bus.Register("verifier-001", agentbus.NewLLMHandler(client,
			"You are the Verifier Agent in TEECheck. Another agent asks you about your verification. Return a JSON object with fields: answer (string), facts (array of strings).",
			cfg.LLMTemp))
	}

	// Register tool handler for mapper (deterministic search)
	reg := scall.NewDefaultRegistry()
	bus.Register("mapper", agentbus.NewToolHandler("mapper", func(ctx context.Context, q agentbus.Query) (agentbus.Response, error) {
		req := staticcheck.CheckRequest{
			RepoRoot: cfg.LocalPath,
			Keywords: strings.Fields(q.Question),
		}
		findings, err := reg.RunAll(ctx, req)
		if err != nil {
			return agentbus.Response{}, err
		}
		var facts []string
		for _, f := range findings {
			facts = append(facts, fmt.Sprintf("%s:%d %s", f.Path, f.StartLine, f.Message))
		}
		return agentbus.Response{
			QueryID:   q.QueryID,
			FromAgent: "mapper",
			Answer:    fmt.Sprintf("Found %d results", len(findings)),
			Facts:     facts,
		}, nil
	}))

	return bus
}
```

- [ ] **Step 2: Add curator command to main.go**

In `cmd/teecheck/main.go`, add after the `"feedback"` case:

```go
case "curator":
	if strings.EqualFold(cfg.CuratorMode, "llm") {
		bus := buildCuratorBus(cfg)
		err = feedback.RunWithBus(cfg, os.Stdout, bus)
	} else {
		err = feedback.Run(cfg, os.Stdout)
	}
```

Add a helper function in main.go:

```go
func buildCuratorBus(cfg config.Config) *agentbus.Bus {
	client := llm.NewClient(cfg)
	maxRounds := cfg.MaxDialogRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	bus := agentbus.New(maxRounds)
	bus.Register("expert-001", agentbus.NewLLMHandler(client,
		"You are the Expert Agent. Another agent asks about your analysis. Return JSON with: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	bus.Register("arbiter-001", agentbus.NewLLMHandler(client,
		"You are the Arbiter Agent. Another agent asks about your judgment. Return JSON with: answer (string), facts (array of strings).",
		cfg.LLMTemp))
	return bus
}
```

Add imports: `"strings"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"`, `"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"`.

- [ ] **Step 3: Verify build and existing tests**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./cmd/teecheck/ && go test ./internal/collabrun/ -v`
Expected: BUILD OK, tests PASS (heuristic path unaffected)

- [ ] **Step 4: Commit**

```bash
git add internal/collabrun/run.go cmd/teecheck/main.go
git commit -m "feat: wire agent bus into collabrun orchestrator and CLI"
```

---

## Task 10: Full Test Suite Verification

**Files:** (no new files)

- [ ] **Step 1: Run all tests**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go test ./... -v`
Expected: All tests PASS, no regressions

- [ ] **Step 2: Verify build**

Run: `cd /root/pp_home/idea/TEECheck/tee-usage-scanner && go build ./cmd/teecheck/`
Expected: clean build

- [ ] **Step 3: Commit (if any fixes needed)**

Only commit if fixes were required.

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Agent bus types | `agentbus/types.go` |
| 2 | Bus implementation | `agentbus/bus.go` |
| 3 | LLM and tool handlers | `agentbus/handlers.go` |
| 4 | Live LLM data source test | `llm/live_test.go` |
| 5 | Config changes | `config/config.go`, `runfs/paths.go` |
| 6 | Verifier LLM mode | `verifier/run.go` |
| 7 | Arbiter LLM mode | `arbiter/run.go` |
| 8 | Curator LLM mode | `feedback/run.go` |
| 9 | Wire bus into orchestrator | `collabrun/run.go`, `main.go` |
| 10 | Full test suite verification | (none) |
