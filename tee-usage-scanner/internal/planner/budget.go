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
