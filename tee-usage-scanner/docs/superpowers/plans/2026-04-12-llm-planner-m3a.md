# LLM Planner M3a — Scaffolding (State + Budget + Loop Detect + Prompt + Wrapper Actions)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the planner package skeleton: `PlannerState` with disk persistence, four-dimensional `Budget`, repetition `LoopDetector`, prompt builders, and the three wrapper/sentinel actions (`done`, `legacy_keyword_scan`, `repomix_summarize`). After M3a all the pieces the planner main loop will assemble exist independently, but there is no main loop yet — that's M3b.

**Architecture:** A new `internal/planner` package with no main loop, just primitive types and helpers. The planner reuses the existing `internal/llm.Client` interface (no need to define a new one — the existing type already has `Generate(ctx, GenerateRequest) (GenerateResponse, error)` which is exactly what we want, and tests can mock it with a tiny struct). Three new actions go under `internal/planner/actions/`. Wrapper actions (`legacy_keyword_scan`, `repomix_summarize`) call into the existing `internal/mapper`, `internal/hotspots`, and `internal/repomix` packages so the L3 planner can choose to use the legacy heuristic path as one tool among many.

**Tech Stack:** Go 1.25, stdlib only (no new dependencies).

**Spec:** `docs/superpowers/specs/2026-04-11-llm-planner-design.md` — sections 3.2 (state machine), 3.3 (context), 4 (action menu), 8 (budget), and 11 (code organization).

**Prereq:** M2 must be merged. Latest commit before M3a should be `90a79a1` (M2 T8 registry helper) or later.

---

## File Structure

### Files created

| Path | Purpose |
|---|---|
| `internal/planner/budget.go` | `Budget` type + `NewDefaultBudget` + `ConsumeRound` + `ConsumeTokens` + `Exhausted` |
| `internal/planner/budget_test.go` | Budget exhaustion in each dimension |
| `internal/planner/loop_detect.go` | `LoopDetector` — repetition + stall detection |
| `internal/planner/loop_detect_test.go` | Repetition rejection, stall detection |
| `internal/planner/state.go` | `PlannerState` + `AppendRound` + persistence to `04_planner/rounds.jsonl` |
| `internal/planner/state_test.go` | State assembly + JSONL persistence |
| `internal/planner/prompt.go` | `BuildSystemPrompt` + `BuildRoundPrompt` |
| `internal/planner/prompt_test.go` | Prompt content assertions |
| `internal/planner/actions/done.go` | `DoneHandler` — terminal action carrying summary + candidates |
| `internal/planner/actions/done_test.go` | Done parses args, returns OK, output is the candidates JSON |
| `internal/planner/actions/legacy_keyword_scan.go` | Wraps existing mapper + hotspots into an action |
| `internal/planner/actions/legacy_keyword_scan_test.go` | Legacy wrapper happy path |
| `internal/planner/actions/repomix_summarize.go` | Wraps `internal/repomix.Pack` into an action |
| `internal/planner/actions/repomix_summarize_test.go` | Repomix wrapper, gated on `npx`/`repomix` availability |

### Files modified

None. M3a is purely additive. M3b will modify `registry_with_sinks.go` to register the new actions.

### Out of scope for M3a

- `planner.go` main loop (Run function) → M3b
- `reverse_trace` action → M3b
- Mocked-LLM end-to-end integration test → M3b
- Pipeline integration (`scanner/scan.go`, `cases/run.go`, `config`) → M4
- Live LLM smoke test → M5

---

## Task 1: Budget

**Files:**
- Create: `internal/planner/budget_test.go` (FIRST)
- Create: `internal/planner/budget.go`

- [ ] **Step 1.1: Write budget tests**

Create `internal/planner/budget_test.go`:

```go
package planner_test

import (
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestBudget_DefaultsMatchSpec(t *testing.T) {
	b := planner.NewDefaultBudget()
	if b.MaxRounds != 8 {
		t.Errorf("MaxRounds = %d, want 8", b.MaxRounds)
	}
	if b.MaxTokens != 120000 {
		t.Errorf("MaxTokens = %d, want 120000", b.MaxTokens)
	}
	if b.PerActionTimeout != 30*time.Second {
		t.Errorf("PerActionTimeout = %v, want 30s", b.PerActionTimeout)
	}
	if b.WallClock != 10*time.Minute {
		t.Errorf("WallClock = %v, want 10m", b.WallClock)
	}
}

func TestBudget_ConsumeRound(t *testing.T) {
	b := planner.NewDefaultBudget()
	b.ConsumeRound()
	if b.RoundsUsed != 1 {
		t.Errorf("RoundsUsed = %d, want 1", b.RoundsUsed)
	}
}

func TestBudget_ConsumeTokens(t *testing.T) {
	b := planner.NewDefaultBudget()
	b.ConsumeTokens(500)
	b.ConsumeTokens(1500)
	if b.TokensUsed != 2000 {
		t.Errorf("TokensUsed = %d, want 2000", b.TokensUsed)
	}
}

func TestBudget_ExhaustedByRounds(t *testing.T) {
	b := planner.Budget{MaxRounds: 2, MaxTokens: 100000, WallClock: time.Hour}
	b.Start()
	b.ConsumeRound()
	if b.Exhausted() {
		t.Fatal("should not be exhausted at 1/2")
	}
	b.ConsumeRound()
	if !b.Exhausted() {
		t.Fatal("should be exhausted at 2/2")
	}
}

func TestBudget_ExhaustedByTokens(t *testing.T) {
	b := planner.Budget{MaxRounds: 100, MaxTokens: 1000, WallClock: time.Hour}
	b.Start()
	b.ConsumeTokens(500)
	if b.Exhausted() {
		t.Fatal("should not be exhausted at 500/1000")
	}
	b.ConsumeTokens(600)
	if !b.Exhausted() {
		t.Fatal("should be exhausted at 1100/1000")
	}
}

func TestBudget_ExhaustedByWallClock(t *testing.T) {
	b := planner.Budget{MaxRounds: 100, MaxTokens: 100000, WallClock: 1 * time.Millisecond}
	b.Start()
	time.Sleep(5 * time.Millisecond)
	if !b.Exhausted() {
		t.Fatal("should be exhausted after wall clock window")
	}
}

func TestBudget_TerminationReason(t *testing.T) {
	tests := []struct {
		name  string
		setup func() planner.Budget
		want  string
	}{
		{
			name: "rounds",
			setup: func() planner.Budget {
				b := planner.Budget{MaxRounds: 1, MaxTokens: 100000, WallClock: time.Hour}
				b.Start()
				b.ConsumeRound()
				return b
			},
			want: "max_rounds",
		},
		{
			name: "tokens",
			setup: func() planner.Budget {
				b := planner.Budget{MaxRounds: 100, MaxTokens: 100, WallClock: time.Hour}
				b.Start()
				b.ConsumeTokens(200)
				return b
			},
			want: "max_tokens",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.setup()
			if got := b.TerminationReason(); got != tt.want {
				t.Errorf("TerminationReason = %q, want %q", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 1.2: Run tests, see compile failure (RED)**

Run: `go test ./internal/planner/ -v`
Expected: `undefined: planner.Budget` etc.

- [ ] **Step 1.3: Implement budget.go**

Create `internal/planner/budget.go`:

```go
// Package planner is the L3 LLM-driven iterative scanner that
// replaces keyword-based hotspot selection. It wraps the action
// registry from internal/planner/actions and drives an LLM through
// a budget-bounded loop of action requests and observations.
//
// M3a contains only the primitives (Budget, LoopDetector,
// PlannerState, prompt builders, wrapper actions). The main loop
// (Run function) lands in M3b.
package planner

import "time"

// Budget bounds the planner loop in four independent dimensions.
// Any single dimension exhausting triggers termination.
type Budget struct {
	MaxRounds        int           // max LLM-driven rounds
	MaxTokens        int           // input + output tokens summed across all rounds
	PerActionTimeout time.Duration // single-action runaway guard
	WallClock        time.Duration // end-to-end hard stop

	// runtime state
	startedAt  time.Time
	RoundsUsed int
	TokensUsed int
}

// NewDefaultBudget returns the spec-default budget:
//   - 8 rounds
//   - 120000 input+output tokens
//   - 30s per action timeout
//   - 10min total wall clock
//
// Per-provider tuning happens at the caller level; this is the
// universal baseline.
func NewDefaultBudget() Budget {
	return Budget{
		MaxRounds:        8,
		MaxTokens:        120000,
		PerActionTimeout: 30 * time.Second,
		WallClock:        10 * time.Minute,
	}
}

// Start records the planner start time. Wall clock checks run
// against this. Call once before the first round.
func (b *Budget) Start() {
	b.startedAt = time.Now()
}

// ConsumeRound increments RoundsUsed.
func (b *Budget) ConsumeRound() {
	b.RoundsUsed++
}

// ConsumeTokens adds n to TokensUsed.
func (b *Budget) ConsumeTokens(n int) {
	b.TokensUsed += n
}

// Exhausted returns true if any dimension has reached its limit.
func (b *Budget) Exhausted() bool {
	return b.TerminationReason() != ""
}

// TerminationReason returns "" if budget remains, otherwise a short
// machine-readable label of which dimension exhausted first.
func (b *Budget) TerminationReason() string {
	if b.MaxRounds > 0 && b.RoundsUsed >= b.MaxRounds {
		return "max_rounds"
	}
	if b.MaxTokens > 0 && b.TokensUsed >= b.MaxTokens {
		return "max_tokens"
	}
	if b.WallClock > 0 && !b.startedAt.IsZero() && time.Since(b.startedAt) >= b.WallClock {
		return "wall_clock"
	}
	return ""
}
```

- [ ] **Step 1.4: Run tests, confirm pass**

Run: `go test ./internal/planner/ -v`
Expected: all 7 budget tests PASS.

- [ ] **Step 1.5: Commit**

```bash
git add internal/planner/budget.go internal/planner/budget_test.go
git commit -m "$(cat <<'EOF'
feat(planner): add four-dimensional Budget with termination reasons

Defines Budget bounding the planner loop in 4 independent dimensions:
max_rounds, max_tokens, per_action_timeout, wall_clock. NewDefaultBudget
returns the spec defaults (8 / 120000 / 30s / 10min).

Exhausted() and TerminationReason() let the main loop (M3b) detect
which dimension exhausted first and emit it in evidence_bundle.meta.

Tests cover defaults, ConsumeRound, ConsumeTokens, exhaustion in each
dimension (rounds, tokens, wall clock), and TerminationReason labels.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Loop detector

**Files:**
- Create: `internal/planner/loop_detect_test.go` (FIRST)
- Create: `internal/planner/loop_detect.go`

- [ ] **Step 2.1: Write loop detector tests**

Create `internal/planner/loop_detect_test.go`:

```go
package planner_test

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestLoopDetector_AcceptsFirst(t *testing.T) {
	d := planner.NewLoopDetector()
	if d.ShouldReject("list_dir", `{"path":"."}`) {
		t.Fatal("first invocation should not be rejected")
	}
}

func TestLoopDetector_RejectsThirdRepetition(t *testing.T) {
	d := planner.NewLoopDetector()
	args := `{"path":"."}`

	if d.ShouldReject("list_dir", args) {
		t.Fatal("call 1 should not be rejected")
	}
	d.Record("list_dir", args)

	if d.ShouldReject("list_dir", args) {
		t.Fatal("call 2 should not be rejected")
	}
	d.Record("list_dir", args)

	if !d.ShouldReject("list_dir", args) {
		t.Fatal("call 3 should be rejected")
	}
}

func TestLoopDetector_DifferentArgsResetCounter(t *testing.T) {
	d := planner.NewLoopDetector()

	d.Record("list_dir", `{"path":"a"}`)
	d.Record("list_dir", `{"path":"a"}`)

	if d.ShouldReject("list_dir", `{"path":"b"}`) {
		t.Fatal("different args should not be rejected even after 2 prior calls")
	}
}

func TestLoopDetector_DifferentActionResetsCounter(t *testing.T) {
	d := planner.NewLoopDetector()
	args := `{"path":"."}`

	d.Record("list_dir", args)
	d.Record("list_dir", args)

	if d.ShouldReject("read_file", args) {
		t.Fatal("different action should not be rejected")
	}
}

func TestLoopDetector_StallDetector(t *testing.T) {
	// StallDetector tracks consecutive rounds with no candidate change.
	// After 2 consecutive no-change rounds it should signal stall.
	s := planner.NewStallDetector()

	s.RecordRound(0)
	if s.Stalled() {
		t.Fatal("first round should not stall")
	}

	s.RecordRound(0)
	if s.Stalled() {
		t.Fatal("second round (1 unchanged) should not stall")
	}

	s.RecordRound(0)
	if !s.Stalled() {
		t.Fatal("third round (2 consecutive unchanged) should stall")
	}
}

func TestLoopDetector_StallResetOnChange(t *testing.T) {
	s := planner.NewStallDetector()
	s.RecordRound(0)
	s.RecordRound(0)
	s.RecordRound(5) // change -> reset
	s.RecordRound(5)
	if s.Stalled() {
		t.Fatal("stall should reset when candidate count changed")
	}
}
```

- [ ] **Step 2.2: Run tests, see compile failure**

Run: `go test ./internal/planner/ -run TestLoopDetector -v`
Expected: `undefined: planner.NewLoopDetector` etc.

- [ ] **Step 2.3: Implement loop_detect.go**

Create `internal/planner/loop_detect.go`:

```go
package planner

// LoopDetector tracks consecutive identical action requests. The
// planner main loop calls ShouldReject before dispatching an action,
// then Record after a successful dispatch. The default policy
// rejects an action when it would be the third consecutive
// identical (action_name, args) tuple.
//
// Identity is based on the action name + the raw args string. Two
// requests with semantically equivalent but textually different args
// are NOT considered identical (this is intentional — the LLM
// should be free to refine).
type LoopDetector struct {
	lastAction string
	lastArgs   string
	count      int
}

func NewLoopDetector() *LoopDetector {
	return &LoopDetector{}
}

// ShouldReject reports whether dispatching this action would be the
// third consecutive identical call.
func (d *LoopDetector) ShouldReject(name, args string) bool {
	if name == d.lastAction && args == d.lastArgs {
		return d.count >= 2
	}
	return false
}

// Record updates the detector after an action dispatch.
func (d *LoopDetector) Record(name, args string) {
	if name == d.lastAction && args == d.lastArgs {
		d.count++
		return
	}
	d.lastAction = name
	d.lastArgs = args
	d.count = 1
}

// StallDetector tracks consecutive rounds with no change to the
// candidate count. After 2 consecutive no-change rounds it signals
// stall (i.e., the LLM is spinning without producing new candidates).
type StallDetector struct {
	lastCount        int
	consecutiveStill int
	hasFirstObs      bool
}

func NewStallDetector() *StallDetector {
	return &StallDetector{}
}

// RecordRound feeds the current candidate count to the detector.
func (s *StallDetector) RecordRound(candidateCount int) {
	if !s.hasFirstObs {
		s.lastCount = candidateCount
		s.consecutiveStill = 0
		s.hasFirstObs = true
		return
	}
	if candidateCount == s.lastCount {
		s.consecutiveStill++
	} else {
		s.consecutiveStill = 0
		s.lastCount = candidateCount
	}
}

// Stalled returns true when the candidate count has been unchanged
// for at least 2 consecutive rounds since the first observation.
func (s *StallDetector) Stalled() bool {
	return s.consecutiveStill >= 2
}
```

- [ ] **Step 2.4: Run tests, confirm pass**

Run: `go test ./internal/planner/ -run TestLoopDetector -v`
Expected: 6 PASS.

- [ ] **Step 2.5: Commit**

```bash
git add internal/planner/loop_detect.go internal/planner/loop_detect_test.go
git commit -m "$(cat <<'EOF'
feat(planner): add LoopDetector and StallDetector

LoopDetector rejects the third consecutive identical (action, args)
tuple — the canonical "LLM is calling the same thing forever"
failure mode. Identity is name + raw args string; the LLM is free
to refine args to escape the loop.

StallDetector signals when the candidate count has been unchanged
for 2 consecutive rounds since the first observation — the "LLM is
spinning without producing new findings" failure mode.

Both detectors are stateless across planner runs (not persisted) and
will be wired into the main loop in M3b.

Tests cover first-call accept, third-rep reject, args-change reset,
action-change reset, stall detection, and stall reset on change.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: PlannerState + persistence

**Files:**
- Create: `internal/planner/state_test.go` (FIRST)
- Create: `internal/planner/state.go`

- [ ] **Step 3.1: Write state tests**

Create `internal/planner/state_test.go`:

```go
package planner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestPlannerState_NewIsEmpty(t *testing.T) {
	s := planner.NewState("run-001")
	if s.RunID != "run-001" {
		t.Errorf("RunID = %q, want run-001", s.RunID)
	}
	if len(s.Rounds) != 0 {
		t.Errorf("Rounds len = %d, want 0", len(s.Rounds))
	}
	if len(s.Candidates) != 0 {
		t.Errorf("Candidates len = %d, want 0", len(s.Candidates))
	}
}

func TestPlannerState_AppendRoundIncrements(t *testing.T) {
	s := planner.NewState("run-001")
	s.AppendRound(artifacts.RoundRecord{Round: 1, Thought: "first"})
	s.AppendRound(artifacts.RoundRecord{Round: 2, Thought: "second"})

	if len(s.Rounds) != 2 {
		t.Fatalf("expected 2 rounds, got %d", len(s.Rounds))
	}
	if s.Rounds[1].Thought != "second" {
		t.Errorf("got %q", s.Rounds[1].Thought)
	}
}

func TestPlannerState_AddCandidates(t *testing.T) {
	s := planner.NewState("run-001")
	s.AddCandidates([]artifacts.Candidate{
		{ID: "c1", Kind: "attestation", Priority: "high"},
	})
	if len(s.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(s.Candidates))
	}
}

func TestPlannerState_PersistRound(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rounds.jsonl")

	s := planner.NewState("run-001")
	if err := s.AppendRoundAndPersist(artifacts.RoundRecord{
		Round:   1,
		Thought: "looking around",
	}, logPath); err != nil {
		t.Fatalf("persist: %v", err)
	}

	if err := s.AppendRoundAndPersist(artifacts.RoundRecord{
		Round:   2,
		Thought: "found something",
	}, logPath); err != nil {
		t.Fatalf("persist: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in jsonl, got %d", len(lines))
	}

	var rr artifacts.RoundRecord
	if err := json.Unmarshal([]byte(lines[0]), &rr); err != nil {
		t.Fatalf("parse line 0: %v", err)
	}
	if rr.Round != 1 || rr.Thought != "looking around" {
		t.Errorf("line 0 = %+v", rr)
	}
}

func TestPlannerState_PersistAppendsNotOverwrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rounds.jsonl")

	s := planner.NewState("run-001")
	for i := 1; i <= 3; i++ {
		if err := s.AppendRoundAndPersist(artifacts.RoundRecord{Round: i}, logPath); err != nil {
			t.Fatal(err)
		}
	}

	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}
```

- [ ] **Step 3.2: Run tests, see compile failure**

Run: `go test ./internal/planner/ -run TestPlannerState -v`
Expected: `undefined: planner.NewState` etc.

- [ ] **Step 3.3: Implement state.go**

Create `internal/planner/state.go`:

```go
package planner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// PlannerState is the working memory of the L3 planner across rounds.
//
// It is structured (not an append-only transcript) to keep the LLM
// prompt size bounded: each round's prompt is built from a snapshot
// of this state, not by replaying the full history. Full history is
// persisted to rounds.jsonl on disk for debugging and post-hoc
// analysis but is not fed back to the LLM.
type PlannerState struct {
	RunID       string                 `json:"run_id"`
	Rounds      []artifacts.RoundRecord `json:"rounds"`
	Candidates  []artifacts.Candidate   `json:"candidates"`
	SinksSeen   []artifacts.SinkHitGroup `json:"sinks_seen,omitempty"`
}

// NewState returns an empty PlannerState bound to a run id.
func NewState(runID string) *PlannerState {
	return &PlannerState{
		RunID: runID,
	}
}

// AppendRound appends a round record to in-memory state. Use
// AppendRoundAndPersist to also write to the rounds.jsonl log.
func (s *PlannerState) AppendRound(r artifacts.RoundRecord) {
	s.Rounds = append(s.Rounds, r)
}

// AppendRoundAndPersist appends the round to in-memory state AND
// writes one JSONL line to logPath. The file is created if missing
// and appended to (not overwritten) on subsequent calls. The parent
// directory is created if missing.
func (s *PlannerState) AppendRoundAndPersist(r artifacts.RoundRecord, logPath string) error {
	s.AppendRound(r)

	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for rounds log: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open rounds log: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal round: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write rounds log: %w", err)
	}
	return nil
}

// AddCandidates appends new candidates to the state. Caller is
// responsible for de-duplication by ID if needed.
func (s *PlannerState) AddCandidates(cands []artifacts.Candidate) {
	s.Candidates = append(s.Candidates, cands...)
}

// LastRoundsForPrompt returns up to n most recent rounds for prompt
// assembly. The full Rounds slice is not fed to the LLM — only this
// trailing window keeps the prompt size bounded.
func (s *PlannerState) LastRoundsForPrompt(n int) []artifacts.RoundRecord {
	if n <= 0 || len(s.Rounds) == 0 {
		return nil
	}
	if len(s.Rounds) <= n {
		out := make([]artifacts.RoundRecord, len(s.Rounds))
		copy(out, s.Rounds)
		return out
	}
	out := make([]artifacts.RoundRecord, n)
	copy(out, s.Rounds[len(s.Rounds)-n:])
	return out
}
```

- [ ] **Step 3.4: Run tests, confirm pass**

Run: `go test ./internal/planner/ -run TestPlannerState -v`
Expected: 5 PASS.

- [ ] **Step 3.5: Commit**

```bash
git add internal/planner/state.go internal/planner/state_test.go
git commit -m "$(cat <<'EOF'
feat(planner): add PlannerState with rounds.jsonl persistence

PlannerState is the working memory of the L3 planner across rounds.
It is structured rather than append-only-transcript so the per-round
prompt size stays bounded: LastRoundsForPrompt returns just the
trailing window the LLM sees, while the full history is persisted
to 04_planner/rounds.jsonl on disk via AppendRoundAndPersist.

The persist path appends (does not overwrite) so a long-running
planner can stream rounds to disk without buffering. The parent
directory is created if missing.

Tests cover empty state, AppendRound, AddCandidates, persist
round-trip, and append-not-overwrite semantics.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Prompt builders

**Files:**
- Create: `internal/planner/prompt_test.go` (FIRST)
- Create: `internal/planner/prompt.go`

- [ ] **Step 4.1: Write prompt tests**

Create `internal/planner/prompt_test.go`:

```go
package planner_test

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestBuildSystemPrompt_MentionsActions(t *testing.T) {
	available := []string{"list_dir", "read_file", "ripgrep", "tree_sitter_outline", "sink_catalog_lookup", "reverse_trace", "done"}
	prompt := planner.BuildSystemPrompt(available)

	for _, name := range available {
		if !strings.Contains(prompt, name) {
			t.Errorf("system prompt missing action %q", name)
		}
	}
}

func TestBuildSystemPrompt_ExplainsResponseFormat(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done"})
	// Must instruct the LLM to return JSON with "thought" and "actions".
	if !strings.Contains(prompt, "thought") {
		t.Error("system prompt missing 'thought' field instruction")
	}
	if !strings.Contains(prompt, "actions") {
		t.Error("system prompt missing 'actions' field instruction")
	}
	if !strings.Contains(prompt, "JSON") && !strings.Contains(prompt, "json") {
		t.Error("system prompt does not mention JSON")
	}
}

func TestBuildRoundPrompt_IncludesProfile(t *testing.T) {
	state := planner.NewState("run-001")
	budget := planner.NewDefaultBudget()
	budget.Start()
	profile := planner.PromptProfile{
		RepoURL:        "https://github.com/example/foo",
		Languages:      []string{"rust"},
		FrameworkHints: []string{"sgx"},
		FileCount:      1234,
	}

	prompt := planner.BuildRoundPrompt(state, profile, budget)
	if !strings.Contains(prompt, "rust") {
		t.Error("round prompt missing language")
	}
	if !strings.Contains(prompt, "sgx") {
		t.Error("round prompt missing framework hint")
	}
	if !strings.Contains(prompt, "1234") {
		t.Error("round prompt missing file count")
	}
}

func TestBuildRoundPrompt_IncludesBudget(t *testing.T) {
	state := planner.NewState("run-001")
	budget := planner.Budget{MaxRounds: 8, MaxTokens: 120000}
	budget.Start()
	budget.ConsumeRound()
	budget.ConsumeRound()
	budget.ConsumeTokens(15000)

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, budget)
	// Should include something like "rounds 2/8" and "tokens 15000/120000"
	if !strings.Contains(prompt, "2/8") && !strings.Contains(prompt, "2 / 8") {
		t.Errorf("round prompt missing rounds budget: %s", prompt)
	}
	if !strings.Contains(prompt, "15000") {
		t.Errorf("round prompt missing tokens used: %s", prompt)
	}
}

func TestBuildRoundPrompt_IncludesRecentObservations(t *testing.T) {
	state := planner.NewState("run-001")
	state.AppendRound(artifacts.RoundRecord{
		Round:   1,
		Thought: "first look",
		Observations: []artifacts.RoundObservation{
			{Name: "list_dir", OK: true, Output: "attest/\nsgx/\n"},
		},
	})
	state.AppendRound(artifacts.RoundRecord{
		Round:   2,
		Thought: "drilling in",
		Observations: []artifacts.RoundObservation{
			{Name: "read_file", OK: true, Output: "1: fn verify_quote() {}"},
		},
	})

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget())
	if !strings.Contains(prompt, "verify_quote") {
		t.Error("round prompt missing recent observation content")
	}
	// Should also include the action names so the LLM sees what was done.
	if !strings.Contains(prompt, "read_file") {
		t.Error("round prompt missing recent action name")
	}
}

func TestBuildRoundPrompt_IncludesCandidatesSoFar(t *testing.T) {
	state := planner.NewState("run-001")
	state.AddCandidates([]artifacts.Candidate{
		{ID: "candidate-001", Kind: "attestation", Paths: []string{"attest/verify.rs"}},
	})

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget())
	if !strings.Contains(prompt, "candidate-001") {
		t.Error("round prompt missing candidate id")
	}
	if !strings.Contains(prompt, "attest/verify.rs") {
		t.Error("round prompt missing candidate path")
	}
}
```

- [ ] **Step 4.2: Run tests, see compile failure**

Run: `go test ./internal/planner/ -run TestBuild -v`
Expected: `undefined: planner.BuildSystemPrompt` etc.

- [ ] **Step 4.3: Implement prompt.go**

Create `internal/planner/prompt.go`:

```go
package planner

import (
	"fmt"
	"strings"
)

// PromptProfile is the minimal view of the project profile the
// planner injects into the round prompt. It is a subset of
// artifacts.ProjectProfile to keep the prompt small and decoupled
// from upstream schema changes.
type PromptProfile struct {
	RepoURL        string
	Commit         string
	Focus          string
	Languages      []string
	FrameworkHints []string
	FileCount      int
}

// BuildSystemPrompt returns the static system prompt the planner
// sends with every LLM request. It explains the agent role, lists
// available actions, and specifies the JSON response format.
func BuildSystemPrompt(availableActions []string) string {
	var b strings.Builder
	b.WriteString("You are TEECheck's L3 security audit planner. Your job is to identify candidate locations in a TEE codebase that warrant deep audit, focused on attestation and key lifecycle.\n\n")

	b.WriteString("AVAILABLE ACTIONS:\n")
	for _, name := range availableActions {
		fmt.Fprintf(&b, "  - %s\n", name)
	}
	b.WriteString("\n")

	b.WriteString("APPROACH:\n")
	b.WriteString("  1. Start by querying sink_catalog_lookup with scope=\"*\" to see what categories exist.\n")
	b.WriteString("  2. Pick 1-2 groups relevant to the project profile, then drill in.\n")
	b.WriteString("  3. Use ripgrep or tree_sitter_outline to find concrete sites for sink categories.\n")
	b.WriteString("  4. Use reverse_trace to walk backward from sinks and identify trust-decision points.\n")
	b.WriteString("  5. When you have enough evidence, call done with your final candidates.\n\n")

	b.WriteString("RESPONSE FORMAT (strict JSON, no extra text):\n")
	b.WriteString(`{
  "thought": "<your reasoning for this round, 1-3 sentences>",
  "actions": [
    {"name": "<action_name>", "args": {<typed args object>}}
  ]
}
`)
	b.WriteString("\nDo not call more than 3 actions per round. Do not repeat the same (action, args) tuple more than twice in a row — the planner will reject it.\n")
	return b.String()
}

// BuildRoundPrompt assembles the user-message prompt for a single
// planner round. It includes the project profile, accumulated
// candidates, the trailing window of recent observations, and the
// remaining budget.
func BuildRoundPrompt(state *PlannerState, profile PromptProfile, budget Budget) string {
	var b strings.Builder

	b.WriteString("=== PROJECT ===\n")
	if profile.RepoURL != "" {
		fmt.Fprintf(&b, "repo: %s\n", profile.RepoURL)
	}
	if profile.Commit != "" {
		fmt.Fprintf(&b, "commit: %s\n", profile.Commit)
	}
	if profile.Focus != "" {
		fmt.Fprintf(&b, "focus: %s\n", profile.Focus)
	}
	if len(profile.Languages) > 0 {
		fmt.Fprintf(&b, "languages: %s\n", strings.Join(profile.Languages, ", "))
	}
	if len(profile.FrameworkHints) > 0 {
		fmt.Fprintf(&b, "frameworks: %s\n", strings.Join(profile.FrameworkHints, ", "))
	}
	if profile.FileCount > 0 {
		fmt.Fprintf(&b, "files: %d\n", profile.FileCount)
	}
	b.WriteString("\n")

	b.WriteString("=== BUDGET ===\n")
	fmt.Fprintf(&b, "rounds: %d/%d\n", budget.RoundsUsed, budget.MaxRounds)
	fmt.Fprintf(&b, "tokens: %d/%d\n", budget.TokensUsed, budget.MaxTokens)
	b.WriteString("\n")

	if len(state.Candidates) > 0 {
		b.WriteString("=== CANDIDATES SO FAR ===\n")
		for _, c := range state.Candidates {
			fmt.Fprintf(&b, "- %s [%s, %s]\n", c.ID, c.Kind, c.Priority)
			if len(c.Paths) > 0 {
				fmt.Fprintf(&b, "  paths: %s\n", strings.Join(c.Paths, ", "))
			}
			if len(c.Symbols) > 0 {
				fmt.Fprintf(&b, "  symbols: %s\n", strings.Join(c.Symbols, ", "))
			}
		}
		b.WriteString("\n")
	}

	recent := state.LastRoundsForPrompt(2)
	if len(recent) > 0 {
		b.WriteString("=== RECENT ROUNDS ===\n")
		for _, r := range recent {
			fmt.Fprintf(&b, "round %d:\n", r.Round)
			if r.Thought != "" {
				fmt.Fprintf(&b, "  thought: %s\n", r.Thought)
			}
			for _, obs := range r.Observations {
				if obs.OK {
					fmt.Fprintf(&b, "  [%s] OK\n", obs.Name)
				} else {
					fmt.Fprintf(&b, "  [%s] ERROR: %s\n", obs.Name, obs.Error)
				}
				if obs.Output != "" {
					trimmed := obs.Output
					if len(trimmed) > 1500 {
						trimmed = trimmed[:1500] + "\n... (truncated)"
					}
					fmt.Fprintf(&b, "    %s\n", strings.ReplaceAll(trimmed, "\n", "\n    "))
				}
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("=== NEXT ===\n")
	b.WriteString("What is your next action? Reply with strict JSON in the format from the system prompt.\n")
	return b.String()
}
```

- [ ] **Step 4.4: Run tests, confirm pass**

Run: `go test ./internal/planner/ -run TestBuild -v`
Expected: 6 PASS.

- [ ] **Step 4.5: Commit**

```bash
git add internal/planner/prompt.go internal/planner/prompt_test.go
git commit -m "$(cat <<'EOF'
feat(planner): add system prompt and round prompt builders

BuildSystemPrompt returns a static prompt explaining the audit role,
listing available actions, and specifying the strict JSON response
format the LLM must return (thought + actions).

BuildRoundPrompt assembles the per-round user message: project
profile snippet, four-dimension budget header, accumulated
candidates list, and the trailing window of the last 2 rounds'
observations. Observations are truncated to 1500 chars to keep
prompt size bounded.

PromptProfile is a small DTO (subset of ProjectProfile) so the
planner package does not pull in the full upstream schema for prompt
assembly.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: done action

**Files:**
- Create: `internal/planner/actions/done_test.go` (FIRST)
- Create: `internal/planner/actions/done.go`

The `done` action is the planner's terminal sentinel. Its args carry the LLM's final summary and candidate list. The action handler validates and returns the parsed payload as the result Output (JSON-encoded). The main loop in M3b will detect `result.Name == "done"` and stop the loop, then unmarshal Output into the final EvidenceBundle.

- [ ] **Step 5.1: Write done tests**

Create `internal/planner/actions/done_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func doneArgs(t *testing.T, summary string, candidates []map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"summary":    summary,
		"candidates": candidates,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDone_ValidArgs(t *testing.T) {
	cands := []map[string]any{
		{
			"id":       "candidate-001",
			"kind":     "attestation",
			"priority": "high",
			"paths":    []string{"attest/verify.rs"},
			"symbols":  []string{"verify_quote"},
			"why_selected": []string{
				"sink:attestation_verification matched",
				"reverse_trace depth 2 from verify_quote",
			},
		},
	}

	h := actions.DoneHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "done",
		Args: doneArgs(t, "audit complete, found 1 candidate", cands),
	})
	if !result.OK {
		t.Fatalf("expected OK, got: %s", result.Error)
	}
	// Output should be JSON containing the summary and candidates.
	if !strings.Contains(result.Output, "candidate-001") {
		t.Fatalf("output missing candidate id: %s", result.Output)
	}
	if !strings.Contains(result.Output, "audit complete") {
		t.Fatalf("output missing summary: %s", result.Output)
	}
}

func TestDone_EmptyCandidatesIsAllowed(t *testing.T) {
	// "found nothing" is a legitimate done state.
	h := actions.DoneHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "done",
		Args: doneArgs(t, "no findings", nil),
	})
	if !result.OK {
		t.Fatalf("expected OK for empty candidates, got: %s", result.Error)
	}
}

func TestDone_InvalidJSON(t *testing.T) {
	h := actions.DoneHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "done",
		Args: json.RawMessage("not json"),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}

func TestDone_NameIsExactlyDone(t *testing.T) {
	h := actions.DoneHandler{}
	if h.Name() != "done" {
		t.Fatalf("Name() = %q, want done", h.Name())
	}
}
```

- [ ] **Step 5.2: Run tests, see compile failure**

Run: `go test ./internal/planner/actions/ -run TestDone -v`
Expected: `undefined: actions.DoneHandler`.

- [ ] **Step 5.3: Implement done.go**

Create `internal/planner/actions/done.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"
)

// DonePayload is the structured payload of the done action — the
// LLM's final summary and candidate list. The planner main loop
// (M3b) unmarshals ActionResult.Output back into this struct after
// detecting result.Name == "done".
type DonePayload struct {
	Summary    string                   `json:"summary"`
	Candidates []map[string]any         `json:"candidates"`
}

// DoneHandler implements the terminal `done` action. It validates
// the LLM's final payload (summary + candidates) and echoes it as
// the result Output (JSON pretty-printed). The main loop detects
// `result.Name == "done"` to stop the planner loop.
//
// candidates is intentionally typed as []map[string]any here, not as
// []artifacts.Candidate, because the LLM may include fields the
// schema does not yet know about. The main loop converts to typed
// Candidate objects when building the final EvidenceBundle.
type DoneHandler struct{}

func (DoneHandler) Name() string { return "done" }

func (DoneHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var payload DonePayload
	if err := json.Unmarshal(req.Args, &payload); err != nil {
		return fail("done", fmt.Sprintf("invalid args: %v", err))
	}

	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fail("done", fmt.Sprintf("marshal payload: %v", err))
	}
	return ActionResult{
		Name:   "done",
		OK:     true,
		Output: string(out),
	}
}
```

- [ ] **Step 5.4: Run tests, confirm pass**

Run: `go test ./internal/planner/actions/ -run TestDone -v`
Expected: 4 PASS.

- [ ] **Step 5.5: Commit**

```bash
git add internal/planner/actions/done.go internal/planner/actions/done_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add done terminal action

The done action carries the LLM's final summary and candidate list.
DonePayload is parsed from args; ActionResult.Output is the JSON
pretty-printed payload. The main loop in M3b detects result.Name ==
"done" and stops, then converts the candidates into typed
artifacts.Candidate objects when building EvidenceBundle.

Candidates are accepted as []map[string]any here to be tolerant of
LLM-side schema drift. Strict typing happens in the main loop.

Tests cover valid args, empty candidates (legitimate "no findings"),
invalid JSON, and the action name.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: legacy_keyword_scan action

**Files:**
- Create: `internal/planner/actions/legacy_keyword_scan_test.go` (FIRST)
- Create: `internal/planner/actions/legacy_keyword_scan.go`

This wraps the existing `internal/mapper.Run` + `internal/hotspots.Run` chain so the LLM can "fall back" to the heuristic path as a single action. It is most useful as a quick low-cost initial scan that produces a hotspot index the LLM can then narrow.

The wrapper takes a run directory (where mapper/hotspots write their outputs) so it can be invoked from inside the planner without polluting the main `runs/<run-id>/` tree. For M3a the test uses `t.TempDir()` directly. M3b/M4 will pass the planner's actual run dir.

- [ ] **Step 6.1: Write the test**

Create `internal/planner/actions/legacy_keyword_scan_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func legacyArgs(t *testing.T, runDir string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"run_dir": runDir})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// writeMinimalRunInputs prepares the manifest, profile, graph, and
// repo_map files that mapper + hotspots expect to read.
func writeMinimalRunInputs(t *testing.T) (runDir string) {
	t.Helper()
	runDir = t.TempDir()

	mustWriteJSON(t, filepath.Join(runDir, "00_manifest.json"), map[string]any{
		"schema_version": "teecheck.manifest.v1",
		"run_id":         "test-run",
		"repo_url":       "https://example.com/repo",
		"commit":         "deadbeef",
		"focus":          "tee",
		"created_at":     "2026-04-12T00:00:00Z",
	})

	mustWriteJSON(t, filepath.Join(runDir, "01_profile", "project_profile.json"), map[string]any{
		"schema_version": "teecheck.project_profile.v1",
		"run_id":         "test-run",
		"languages":      []string{"rust"},
	})

	// Minimal graph with one rust file node so repomap has something to chew on.
	mustWriteJSON(t, filepath.Join(runDir, "02_graph", "graph.json"), map[string]any{
		"nodes": []map[string]any{
			{
				"id":       "n1",
				"kind":     "file",
				"name":     "verify.rs",
				"path":     "src/attest/verify.rs",
				"language": "rust",
			},
			{
				"id":       "n2",
				"kind":     "function",
				"name":     "verify_quote",
				"path":     "src/attest/verify.rs",
				"language": "rust",
			},
		},
		"edges": []map[string]any{
			{"source": "n1", "target": "n2", "kind": "contains"},
		},
	})

	return runDir
}

func mustWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyKeywordScan_HappyPath(t *testing.T) {
	runDir := writeMinimalRunInputs(t)

	h := actions.LegacyKeywordScanHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "legacy_keyword_scan",
		Args: legacyArgs(t, runDir),
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	// Output should mention hotspot count.
	if !strings.Contains(result.Output, "hotspot") {
		t.Fatalf("output missing hotspot mention: %s", result.Output)
	}

	// Confirm hotspot_index.json was actually written.
	if _, err := os.Stat(filepath.Join(runDir, "02_hotspots", "hotspot_index.json")); err != nil {
		t.Fatalf("hotspot_index.json not written: %v", err)
	}
}

func TestLegacyKeywordScan_MissingRunDir(t *testing.T) {
	h := actions.LegacyKeywordScanHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "legacy_keyword_scan",
		Args: legacyArgs(t, "/nonexistent"),
	})
	if result.OK {
		t.Fatal("expected failure for missing run dir")
	}
}

func TestLegacyKeywordScan_InvalidJSON(t *testing.T) {
	h := actions.LegacyKeywordScanHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name: "legacy_keyword_scan",
		Args: json.RawMessage("not json"),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}
```

- [ ] **Step 6.2: Run tests, see compile failure**

Run: `go test ./internal/planner/actions/ -run TestLegacyKeywordScan -v`
Expected: `undefined: actions.LegacyKeywordScanHandler`.

- [ ] **Step 6.3: Implement legacy_keyword_scan.go**

Create `internal/planner/actions/legacy_keyword_scan.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/hotspots"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/mapper"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type legacyKeywordScanArgs struct {
	RunDir      string `json:"run_dir"`
	MaxHotspots int    `json:"max_hotspots,omitempty"`
}

// LegacyKeywordScanHandler wraps the existing mapper + hotspots
// chain (the pre-L3 heuristic hotspot picker) into a planner action.
//
// The L3 LLM can call this as a low-cost initial scan that produces
// a hotspot_index.json the LLM then narrows. It is the action-shaped
// mirror of "fall back to heuristic mode if all else fails".
//
// The action expects manifest + profile + graph + repo_map files to
// already exist in the run directory (the planner's own preprocessor
// stage writes these before the loop starts).
type LegacyKeywordScanHandler struct{}

func (LegacyKeywordScanHandler) Name() string { return "legacy_keyword_scan" }

func (LegacyKeywordScanHandler) Run(_ context.Context, req ActionRequest) ActionResult {
	var args legacyKeywordScanArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("invalid args: %v", err))
	}
	if args.RunDir == "" {
		return fail("legacy_keyword_scan", "run_dir is required")
	}
	if args.MaxHotspots <= 0 {
		args.MaxHotspots = 12
	}

	cfg := config.Config{
		RunDir:        args.RunDir,
		MaxHotspots:   args.MaxHotspots,
		GraphJSONPath: runfs.GraphPath(args.RunDir),
	}

	if err := mapper.Run(cfg); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("mapper: %v", err))
	}
	if err := hotspots.Run(cfg); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("hotspots: %v", err))
	}

	var index artifacts.HotspotIndex
	if err := runfs.ReadJSON(runfs.HotspotIndexPath(args.RunDir), &index); err != nil {
		return fail("legacy_keyword_scan", fmt.Sprintf("read hotspot_index: %v", err))
	}

	return ActionResult{
		Name:   "legacy_keyword_scan",
		OK:     true,
		Output: fmt.Sprintf("legacy keyword scan produced %d hotspots in %s", len(index.Hotspots), runfs.HotspotIndexPath(args.RunDir)),
	}
}
```

- [ ] **Step 6.4: Run tests, confirm pass**

Run: `go test ./internal/planner/actions/ -run TestLegacyKeywordScan -v`
Expected: 3 PASS.

If `TestLegacyKeywordScan_HappyPath` fails because the existing mapper/hotspots packages have a different config field (e.g., `cfg.RepoRoot` is required), inspect the existing code in `internal/mapper/run.go` and `internal/hotspots/run.go`, add the missing fields to `cfg`, and try again. If you cannot get the wrapper to call the existing code without modifying the existing code, **STOP and report DONE_WITH_CONCERNS** describing what you found — do not modify mapper/hotspots themselves.

- [ ] **Step 6.5: Commit**

```bash
git add internal/planner/actions/legacy_keyword_scan.go internal/planner/actions/legacy_keyword_scan_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add legacy_keyword_scan wrapper action

Wraps the existing mapper + hotspots chain into a planner action so
the L3 LLM can request a low-cost heuristic scan as one tool among
many. The action assumes manifest + profile + graph already exist
in the run directory (the planner's preprocessor stage writes these
before the loop starts).

Output is a one-line summary of the produced hotspot count plus
the on-disk path. The actual hotspot_index.json is written by the
wrapped hotspots package.

This is the architectural realization of "old keyword scoring as a
tool, not a replacement" from spec section 7.

Tests cover happy path with synthetic graph, missing run dir, and
invalid args.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: repomix_summarize action

**Files:**
- Create: `internal/planner/actions/repomix_summarize_test.go` (FIRST)
- Create: `internal/planner/actions/repomix_summarize.go`

This wraps the existing `internal/repomix.Pack` so the LLM can request a compressed summary of a subtree. The repomix CLI is invoked via `npx repomix`, which requires Node.js + npx in PATH. The test gates on availability and skips otherwise.

- [ ] **Step 7.1: Write the test**

Create `internal/planner/actions/repomix_summarize_test.go`:

```go
package actions_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func requireRepomix(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("npx not installed; skipping repomix action tests")
	}
}

func repomixArgs(t *testing.T, path string, compress bool) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"path":     path,
		"compress": compress,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRepomixSummarize_HappyPath(t *testing.T) {
	requireRepomix(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn verify_quote() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, ".", false),
		RepoRoot: dir,
	})
	if !result.OK {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	// Output should contain something from the file.
	if !strings.Contains(result.Output, "a.rs") && !strings.Contains(result.Output, "verify_quote") {
		t.Fatalf("output missing expected content: %s", result.Output)
	}
}

func TestRepomixSummarize_EscapeRejected(t *testing.T) {
	requireRepomix(t)
	dir := t.TempDir()

	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, "../../etc", false),
		RepoRoot: dir,
	})
	if result.OK {
		t.Fatal("expected failure for escape path")
	}
}

func TestRepomixSummarize_InvalidJSON(t *testing.T) {
	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     json.RawMessage("not json"),
		RepoRoot: t.TempDir(),
	})
	if result.OK {
		t.Fatal("expected failure for invalid args")
	}
}

func TestRepomixSummarize_MissingNpx(t *testing.T) {
	if _, err := exec.LookPath("npx"); err == nil {
		t.Skip("npx is installed; cannot test missing-npx path")
	}
	h := actions.RepomixSummarizeHandler{}
	result := h.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, ".", false),
		RepoRoot: t.TempDir(),
	})
	if result.OK {
		t.Fatal("expected failure when npx missing")
	}
}
```

- [ ] **Step 7.2: Run tests, see compile failure**

Run: `go test ./internal/planner/actions/ -run TestRepomixSummarize -v`
Expected: `undefined: actions.RepomixSummarizeHandler`.

- [ ] **Step 7.3: Implement repomix_summarize.go**

Create `internal/planner/actions/repomix_summarize.go`:

```go
package actions

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repomix"
)

const repomixOutputCap = 50000

type repomixSummarizeArgs struct {
	Path     string `json:"path"`
	Compress bool   `json:"compress"`
}

// RepomixSummarizeHandler wraps internal/repomix.Pack into a planner
// action. The LLM can request a compressed view of a subtree to
// orient itself before drilling in with read_file or
// tree_sitter_outline.
//
// repomix shells out to `npx repomix`, which requires Node.js and
// npx in PATH. If unavailable, the action returns OK=false with a
// clear error so the LLM can fall back.
//
// Output is capped at repomixOutputCap bytes (50KB) to prevent the
// LLM context from being blown by a massive monorepo summary.
type RepomixSummarizeHandler struct{}

func (RepomixSummarizeHandler) Name() string { return "repomix_summarize" }

func (RepomixSummarizeHandler) Run(ctx context.Context, req ActionRequest) ActionResult {
	var args repomixSummarizeArgs
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return fail("repomix_summarize", fmt.Sprintf("invalid args: %v", err))
	}
	if !repomix.Available() {
		return fail("repomix_summarize", "npx (required by repomix) not installed")
	}

	full, err := ResolvePath(req.RepoRoot, args.Path)
	if err != nil {
		return fail("repomix_summarize", err.Error())
	}

	result, err := repomix.Pack(ctx, repomix.PackRequest{
		RepoRoot: full,
		Compress: args.Compress,
	})
	if err != nil {
		return fail("repomix_summarize", fmt.Sprintf("repomix: %v", err))
	}

	output := repomix.FormatForPrompt(result, repomixOutputCap)
	truncated := len(output) >= repomixOutputCap
	return ActionResult{
		Name:      "repomix_summarize",
		OK:        true,
		Output:    output,
		Truncated: truncated,
	}
}
```

- [ ] **Step 7.4: Run tests, confirm pass**

Run: `go test ./internal/planner/actions/ -run TestRepomixSummarize -v`
Expected: tests PASS or SKIP if `npx` is not installed. The escape-rejected test runs even without npx (it requires npx because of the `requireRepomix` gate at the top — that's fine, it'll just be skipped on machines without npx). The invalid-JSON test runs without npx because the JSON parse fails before the npx check.

Wait — looking again at the test, `TestRepomixSummarize_EscapeRejected` calls `requireRepomix(t)` first, so it skips without npx. But the implementation rejects the escape path AFTER checking npx availability — so on a machine without npx, the action returns "npx not installed" rather than "escape" error. The test would skip in that case, which is fine.

`TestRepomixSummarize_InvalidJSON` does NOT require npx because it fails before the availability check. Verify by reading the implementation.

- [ ] **Step 7.5: Commit**

```bash
git add internal/planner/actions/repomix_summarize.go internal/planner/actions/repomix_summarize_test.go
git commit -m "$(cat <<'EOF'
feat(planner/actions): add repomix_summarize wrapper action

Wraps internal/repomix.Pack into a planner action so the L3 LLM can
request a compressed view of a subtree to orient itself before
drilling in with read_file or tree_sitter_outline.

Output is capped at 50KB via repomix.FormatForPrompt to prevent the
LLM context from being blown by a massive monorepo summary.

repomix shells out to npx; the action returns a clean "not
installed" error when npx is missing so the LLM can fall back to
list_dir/read_file.

Tests are gated on npx availability and skip cleanly when it is
not installed. Invalid-args test runs unconditionally.

Part of M3a.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Full M3a sweep

**Files:** None — verification only.

- [ ] **Step 8.1: Run all planner package tests**

Run: `go test ./internal/planner/...`
Expected: all PASS, no skips on Linux except possibly TestRepomixSummarize_HappyPath if npx is unavailable.

- [ ] **Step 8.2: Run the full project test suite**

Run: `go test ./...`
Expected: no new failures.

- [ ] **Step 8.3: go vet**

Run: `go vet ./...`
Expected: exit 0.

- [ ] **Step 8.4: Build the binary**

Run: `go build -o /tmp/teecheck-m3a ./cmd/teecheck/`
Expected: exit 0, binary produced.

- [ ] **Step 8.5: Mark M3a complete**

Reply: "M3a complete. Ready for M3b planning."

---

## Post-M3a

After M3a lands, request an M3b plan covering:

- `internal/planner/actions/reverse_trace.go` — BFS backward through call sites using tree-sitter (the substantial new action)
- `internal/planner/planner.go` — `Run(ctx, RunConfig) RunResult` main loop
- `internal/planner/planner_test.go` — direct unit tests for the loop's termination paths
- `internal/planner/planner_integration_test.go` — mocked LLM end-to-end test that drives a full audit on a small Rust fixture and verifies the produced EvidenceBundle

M3b's main risk is the LLM-loop integration: parsing the LLM JSON response into action requests, threading state between rounds, building the final EvidenceBundle from the done payload. The mocked-LLM integration test is the gate before M4 (pipeline integration) and M5 (live LLM smoke).
