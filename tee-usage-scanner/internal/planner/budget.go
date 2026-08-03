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
	MaxRounds        int           // max investigation rounds
	MaxTokens        int           // input + output tokens summed across all rounds
	PerActionTimeout time.Duration // single-action runaway guard
	WallClock        time.Duration // end-to-end hard stop

	// MaxReconRounds is the reconnaissance allowance, granted on top of
	// MaxRounds rather than out of it.
	//
	// Sharing one pool would make browsing cost investigation: a Planner
	// that spent five rounds understanding the project would reach its
	// first lead with three rounds left, and the cheapest way to keep
	// rounds for the work would be to skip the looking. Rounds spent in
	// reconnaissance raise the ceiling by the same amount, up to this cap;
	// past the cap the gate releases and further browsing does come out of
	// the investigation pool, which is the right incentive at that point.
	MaxReconRounds int

	// runtime state
	startedAt       time.Time
	RoundsUsed      int
	ReconRoundsUsed int
	TokensUsed      int
}

// NewDefaultBudget returns the spec-default budget:
//   - 8 investigation rounds
//   - 6 reconnaissance rounds on top of them
//   - 120000 input+output tokens
//   - 30s per action timeout
//   - 10min total wall clock
//
// Six reconnaissance rounds is what the indexed gate costs at three actions
// a round: the repository card, five modules listed, fifteen function cards
// opened and one relation query is nineteen actions, and a model that spends
// a round deciding where to look next needs the slack.
//
// Per-provider tuning happens at the caller level; this is the
// universal baseline.
func NewDefaultBudget() Budget {
	return Budget{
		MaxRounds:        8,
		MaxReconRounds:   6,
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

// ConsumeReconRound spends a round on reconnaissance. It counts against the
// total like any round, and additionally draws on the reconnaissance
// allowance until that is used up.
func (b *Budget) ConsumeReconRound() {
	b.RoundsUsed++
	if b.ReconRoundsUsed < b.MaxReconRounds {
		b.ReconRoundsUsed++
	}
}

// ReconExhausted reports whether the reconnaissance allowance is spent. When
// it is, the gate stops blocking and the Planner is told to open a lead with
// what it has.
func (b *Budget) ReconExhausted() bool {
	return b.ReconRoundsUsed >= b.MaxReconRounds
}

// TotalRounds is this run's round ceiling: the investigation budget plus the
// reconnaissance rounds granted so far. It grows as reconnaissance is spent
// and stops growing at MaxRounds + MaxReconRounds.
func (b *Budget) TotalRounds() int {
	return b.MaxRounds + b.ReconRoundsUsed
}

// IsFinalRound reports whether the round just consumed is the last one. The
// forced-`done` prompt fires on it, and the reconnaissance gate steps aside
// for it — the model cannot be told both "you MUST call done" and "done is
// refused".
func (b *Budget) IsFinalRound() bool {
	return b.MaxRounds > 0 && b.RoundsUsed >= b.TotalRounds()
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
	if b.MaxRounds > 0 && b.RoundsUsed >= b.TotalRounds() {
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
