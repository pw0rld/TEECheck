package pipeline

import (
	"reflect"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestConfiguredPlannerBudgetTaintControls(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		queries int
		timeout time.Duration
	}{
		{"old programmatic config", config.Config{}, 8, 5 * time.Minute},
		{"positive override", config.Config{MaxTaintQueries: 3, TaintQueryTimeout: 2 * time.Minute}, 3, 2 * time.Minute},
		{"explicit unlimited", config.Config{MaxTaintQueries: 0, MaxTaintQueriesExplicit: true}, 0, 5 * time.Minute},
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

func TestConfiguredPlannerTokenLimits(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		cfg                         config.Config
		total, recon, investigation int
	}{
		{"old programmatic zero keeps defaults", config.Config{}, 240000, 100000, 140000},
		{"positive overrides", config.Config{PlannerMaxTokens: 600000, PlannerMaxReconTokens: 250000, PlannerMaxInvestigationTokens: 350000}, 600000, 250000, 350000},
		{"unlimited aggregate retains phases", config.Config{PlannerMaxTokensExplicit: true}, 0, 100000, 140000},
		{"unlimited recon retains other caps", config.Config{PlannerMaxReconTokensExplicit: true}, 240000, 0, 140000},
		{"unlimited investigation retains other caps", config.Config{PlannerMaxInvestigationTokensExplicit: true}, 240000, 100000, 0},
		{"all unlimited", config.Config{PlannerMaxTokensExplicit: true, PlannerMaxReconTokensExplicit: true, PlannerMaxInvestigationTokensExplicit: true}, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := configuredPlannerBudget(tc.cfg)
			if got.MaxTokens != tc.total || got.MaxReconTokens != tc.recon || got.MaxInvestigationTokens != tc.investigation {
				t.Fatalf("token limits = %d/%d/%d, want %d/%d/%d", got.MaxTokens, got.MaxReconTokens, got.MaxInvestigationTokens, tc.total, tc.recon, tc.investigation)
			}
			baseline := planner.NewDefaultBudget()
			if got.MaxRounds != baseline.MaxRounds || got.MaxReconRounds != baseline.MaxReconRounds || got.WallClock != baseline.WallClock || got.ConvergenceReserveTokens != baseline.ConvergenceReserveTokens {
				t.Fatal("token override changed unrelated planner limits")
			}
		})
	}
}

func TestResumeSettingsIncludePlannerTokenLimits(t *testing.T) {
	cfg := config.Config{KnowledgeRoot: t.TempDir()}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []config.Config{
		{KnowledgeRoot: cfg.KnowledgeRoot, PlannerMaxTokensExplicit: true},
		{KnowledgeRoot: cfg.KnowledgeRoot, PlannerMaxReconTokensExplicit: true},
		{KnowledgeRoot: cfg.KnowledgeRoot, PlannerMaxInvestigationTokensExplicit: true},
	} {
		updated, err := resolvedResumeSettings(changed, roles)
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(baseline, updated) {
			t.Fatal("resume settings ignored a disabled token limit")
		}
	}
}
