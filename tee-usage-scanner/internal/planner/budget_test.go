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
	if b.MaxTokens != 240000 {
		t.Errorf("MaxTokens = %d, want 240000", b.MaxTokens)
	}
	if b.PerActionTimeout != 30*time.Second {
		t.Errorf("PerActionTimeout = %v, want 30s", b.PerActionTimeout)
	}
	if b.WallClock != 10*time.Minute {
		t.Errorf("WallClock = %v, want 10m", b.WallClock)
	}
	if b.MaxTaintQueries != 8 || b.TaintQueryTimeout != 5*time.Minute {
		t.Errorf("taint controls = %d / %v, want 8 / 5m", b.MaxTaintQueries, b.TaintQueryTimeout)
	}
}

func TestBudget_TaintQuotaCountsOnlyDispatchedQueries(t *testing.T) {
	b := planner.NewDefaultBudget()
	b.MaxTaintQueries = 2
	for i := 0; i < 5; i++ {
		if !b.CanRunTaintQuery() {
			t.Fatal("checking an available cache path consumed the quota")
		}
	}
	if b.TaintQueriesUsed != 0 {
		t.Fatal("cache lookup changed usage")
	}
	if !b.ConsumeTaintQuery() || !b.ConsumeTaintQuery() {
		t.Fatal("allowed query was refused")
	}
	if b.CanRunTaintQuery() || b.ConsumeTaintQuery() || b.TaintQueriesUsed != 2 {
		t.Fatalf("quota exceeded or usage changed: %+v", b)
	}
	if b.Exhausted() {
		t.Fatal("a spent taint quota must not stop browsing or finalization")
	}
}

func TestBudget_ZeroTaintQuotaIsUnlimited(t *testing.T) {
	b := planner.NewDefaultBudget()
	b.MaxTaintQueries = 0
	for i := 0; i < 100; i++ {
		if !b.CanRunTaintQuery() || !b.ConsumeTaintQuery() {
			t.Fatalf("unlimited quota refused query %d", i)
		}
	}
	if b.TaintQueriesUsed != 100 {
		t.Fatalf("unlimited queries must still be accounted: %d", b.TaintQueriesUsed)
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

func TestBudget_OutputAllowanceIndependentTokenCaps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		b     planner.Budget
		input int
		recon bool
		final bool
		want  int
	}{
		{name: "no caps", want: planner.UnlimitedOutputAllowance},
		{name: "reserve alone is not a cap", b: planner.Budget{ConvergenceReserveTokens: 20000}, input: 35000, want: planner.UnlimitedOutputAllowance},
		{name: "inactive phase does not cap recon", b: planner.Budget{MaxInvestigationTokens: 100}, recon: true, want: planner.UnlimitedOutputAllowance},
		{name: "inactive phase does not cap investigation", b: planner.Budget{MaxReconTokens: 100}, want: planner.UnlimitedOutputAllowance},
		{name: "total disabled recon enabled", b: planner.Budget{MaxReconTokens: 100, ReconTokensUsed: 25, ConvergenceReserveTokens: 20}, input: 10, recon: true, want: 65},
		{name: "total disabled investigation enabled", b: planner.Budget{MaxInvestigationTokens: 100, InvestigationTokensUsed: 25, ConvergenceReserveTokens: 20}, input: 10, want: 45},
		{name: "phase disabled total enabled", b: planner.Budget{MaxTokens: 100, TokensUsed: 25, ConvergenceReserveTokens: 20}, input: 10, want: 45},
		{name: "final spends reserve", b: planner.Budget{MaxInvestigationTokens: 100, InvestigationTokensUsed: 25, ConvergenceReserveTokens: 20}, input: 10, final: true, want: 65},
		{name: "tighter phase wins", b: planner.Budget{MaxTokens: 1000, TokensUsed: 200, MaxInvestigationTokens: 200, InvestigationTokensUsed: 50, ConvergenceReserveTokens: 20}, input: 10, want: 120},
		{name: "tighter total wins", b: planner.Budget{MaxTokens: 100, TokensUsed: 25, MaxInvestigationTokens: 200, InvestigationTokensUsed: 50, ConvergenceReserveTokens: 20}, input: 10, want: 45},
		{name: "finite exhausted is zero", b: planner.Budget{MaxTokens: 10, TokensUsed: 10}, want: 0},
		{name: "input consumes remaining", b: planner.Budget{MaxTokens: 100}, input: 100, want: 0},
		{name: "reserve consumes remaining", b: planner.Budget{MaxInvestigationTokens: 100, ConvergenceReserveTokens: 200}, want: 0},
		{name: "provider overrun saturates", b: planner.Budget{MaxTokens: 100, TokensUsed: int(^uint(0) >> 1)}, input: 1000, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.b.OutputAllowance(tc.input, tc.recon, tc.final); got != tc.want {
				t.Fatalf("OutputAllowance = %d, want %d", got, tc.want)
			}
		})
	}
}
