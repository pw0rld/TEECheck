package pipeline

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

// Use the same budget for execution and the recorded manifest. Extending a
// deep run is explicit, so ordinary runs remain comparable to the 10m baseline.
func configuredPlannerBudget(cfg config.Config) planner.Budget {
	b := planner.NewDefaultBudget()
	if cfg.PlannerWallClock > 0 {
		b.WallClock = cfg.PlannerWallClock
	}
	if cfg.PlannerMaxTokensExplicit || cfg.PlannerMaxTokens > 0 {
		b.MaxTokens = cfg.PlannerMaxTokens
	}
	if cfg.PlannerMaxReconTokensExplicit || cfg.PlannerMaxReconTokens > 0 {
		b.MaxReconTokens = cfg.PlannerMaxReconTokens
	}
	if cfg.PlannerMaxInvestigationTokensExplicit || cfg.PlannerMaxInvestigationTokens > 0 {
		b.MaxInvestigationTokens = cfg.PlannerMaxInvestigationTokens
	}
	if cfg.MaxTaintQueriesExplicit || cfg.MaxTaintQueries > 0 {
		b.MaxTaintQueries = cfg.MaxTaintQueries
	}
	if cfg.TaintQueryTimeout > 0 {
		b.TaintQueryTimeout = cfg.TaintQueryTimeout
	}
	return b
}
