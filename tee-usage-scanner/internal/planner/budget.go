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
	MaxRounds                int           // max investigation rounds
	MaxTokens                int           // input + output tokens summed across all rounds
	MaxReconTokens           int           // reconnaissance input + output allowance
	MaxInvestigationTokens   int           // investigation allowance, including convergence
	ConvergenceReserveTokens int           // reserved inside total/investigation limits for final done
	PerActionTimeout         time.Duration // single-action runaway guard
	WallClock                time.Duration // end-to-end hard stop
	// Taint queries use their own timeout and quota because a global query
	// can legitimately take longer than a source browsing action. Zero quota
	// means no separate cap; ordinary run budgets still apply.
	MaxTaintQueries   int
	TaintQueryTimeout time.Duration

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
	startedAt               time.Time
	RoundsUsed              int
	ReconRoundsUsed         int
	TokensUsed              int
	ReconTokensUsed         int
	InvestigationTokensUsed int
	TaintQueriesUsed        int
}

// NewDefaultBudget returns the spec-default budget:
//   - 8 investigation rounds
//   - 10 reconnaissance rounds on top of them
//   - 200000 input+output tokens (60000 recon, 140000 investigation)
//   - 20000 investigation tokens reserved for convergence
//   - 30s per action timeout
//   - 10min total wall clock
//   - 8 uncached taint queries, with 90s per query
//
// The indexed gate needs eleven successful actions (one repository card,
// three module listings, six function cards and one relation query). The
// remaining reconnaissance rounds allow failures and source inspection.
func NewDefaultBudget() Budget {
	return Budget{
		MaxRounds:                8,
		MaxReconRounds:           10,
		MaxTokens:                200000,
		MaxReconTokens:           60000,
		MaxInvestigationTokens:   140000,
		ConvergenceReserveTokens: 20000,
		PerActionTimeout:         30 * time.Second,
		WallClock:                10 * time.Minute,
		MaxTaintQueries:          8,
		TaintQueryTimeout:        90 * time.Second,
	}
}

// CanRunTaintQuery checks only the separate query allowance. Exhausting this
// quota leaves source browsing and finalization available. Cache hits do not
// call ConsumeTaintQuery and remain usable after the quota has been spent.
func (b Budget) CanRunTaintQuery() bool {
	return b.MaxTaintQueries == 0 || (b.MaxTaintQueries > 0 && b.TaintQueriesUsed < b.MaxTaintQueries)
}

// ConsumeTaintQuery charges one dispatched, uncached query. Failed dispatches
// still count as work; merely validating arguments or reading a cache does not.
func (b *Budget) ConsumeTaintQuery() bool {
	if !b.CanRunTaintQuery() {
		return false
	}
	b.TaintQueriesUsed++
	return true
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
	if b.MaxRounds > 0 && b.RoundsUsed >= b.TotalRounds() {
		return true
	}
	if b.ConvergenceReserveTokens <= 0 {
		return false
	}
	return (b.MaxTokens > 0 && b.MaxTokens-b.TokensUsed <= b.ConvergenceReserveTokens) ||
		(b.MaxInvestigationTokens > 0 && b.MaxInvestigationTokens-b.InvestigationTokensUsed <= b.ConvergenceReserveTokens)
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

// ConsumePhaseTokens records actual token usage even when a provider exceeds
// its request limit: overruns must remain visible instead of being clamped.
func (b *Budget) ConsumePhaseTokens(n int, recon bool) {
	b.ConsumeTokens(n)
	if recon {
		b.ReconTokensUsed += n
	} else {
		b.InvestigationTokensUsed += n
	}
}

func (b Budget) ReconTokenExhausted() bool {
	return b.MaxReconTokens > 0 && b.ReconTokensUsed >= b.MaxReconTokens
}

// OutputAllowance bounds a request's output after conservatively reserving
// its input and the final-answer reserve. A zero phase limit means unlimited
// for compatibility with callers supplying older custom budgets.
func (b Budget) OutputAllowance(input int, recon, final bool) int {
	remaining := int(^uint(0) >> 1)
	limit := func(max, used int) {
		if max > 0 && max-used-input < remaining {
			remaining = max - used - input
		}
	}
	limit(b.MaxTokens, b.TokensUsed)
	if !final {
		remaining -= b.ConvergenceReserveTokens
	}
	if recon {
		if b.MaxReconTokens > 0 && b.MaxReconTokens-b.ReconTokensUsed-input < remaining {
			remaining = b.MaxReconTokens - b.ReconTokensUsed - input
		}
	} else if b.MaxInvestigationTokens > 0 {
		phaseRemaining := b.MaxInvestigationTokens - b.InvestigationTokensUsed - input
		if !final {
			phaseRemaining -= b.ConvergenceReserveTokens
		}
		if phaseRemaining < remaining {
			remaining = phaseRemaining
		}
	}
	if remaining < 0 {
		return 0
	}
	return remaining
}
