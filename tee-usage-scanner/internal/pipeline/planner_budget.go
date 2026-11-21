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
	return b
}
