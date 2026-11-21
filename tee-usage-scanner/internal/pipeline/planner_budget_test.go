package pipeline

import (
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
)

func TestConfiguredPlannerBudgetTaintControls(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		queries int
		timeout time.Duration
	}{
		{"old programmatic config", config.Config{}, 8, 90 * time.Second},
		{"positive override", config.Config{MaxTaintQueries: 3, TaintQueryTimeout: 2 * time.Minute}, 3, 2 * time.Minute},
		{"explicit unlimited", config.Config{MaxTaintQueries: 0, MaxTaintQueriesExplicit: true}, 0, 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := configuredPlannerBudget(tc.cfg)
			if budget.MaxTaintQueries != tc.queries || budget.TaintQueryTimeout != tc.timeout {
				t.Fatalf("taint budget=%d/%v want %d/%v", budget.MaxTaintQueries, budget.TaintQueryTimeout, tc.queries, tc.timeout)
			}
			if budget.WallClock != 10*time.Minute {
				t.Fatal("taint settings changed the wall-clock baseline")
			}
		})
	}
}
