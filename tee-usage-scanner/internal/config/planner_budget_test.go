package config

import (
	"strings"
	"testing"
)

func TestPlannerTokenFlagsDefaultsAndExplicitLimits(t *testing.T) {
	streamTestEnvironment(t)
	for _, command := range []string{"run", "plan"} {
		t.Run(command, func(t *testing.T) {
			defaults, err := Parse([]string{command, "."})
			if err != nil {
				t.Fatal(err)
			}
			if defaults.PlannerMaxTokens != 240000 || defaults.PlannerMaxReconTokens != 100000 || defaults.PlannerMaxInvestigationTokens != 140000 {
				t.Fatalf("unexpected token defaults: %+v", defaults)
			}
			if defaults.PlannerMaxTokensExplicit || defaults.PlannerMaxReconTokensExplicit || defaults.PlannerMaxInvestigationTokensExplicit {
				t.Fatal("default token limits were marked explicit")
			}
			for _, limit := range []string{"0", "500000"} {
				cfg, err := Parse([]string{command, ".", "--planner-max-tokens", limit, "--planner-max-recon-tokens", limit, "--planner-max-investigation-tokens", limit})
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if limit != "0" {
					want = 500000
				}
				if cfg.PlannerMaxTokens != want || cfg.PlannerMaxReconTokens != want || cfg.PlannerMaxInvestigationTokens != want {
					t.Fatalf("explicit %s token limits lost: %+v", limit, cfg)
				}
				if !cfg.PlannerMaxTokensExplicit || !cfg.PlannerMaxReconTokensExplicit || !cfg.PlannerMaxInvestigationTokensExplicit {
					t.Fatalf("explicit flags lost for %s", limit)
				}
			}
		})
	}
}

func TestPlannerTokenFlagsRemainIndependent(t *testing.T) {
	streamTestEnvironment(t)
	cfg, err := Parse([]string{"run", "--planner-max-tokens=0", "."})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PlannerMaxTokens != 0 || !cfg.PlannerMaxTokensExplicit || cfg.PlannerMaxReconTokens != 100000 || cfg.PlannerMaxInvestigationTokens != 140000 || cfg.PlannerMaxReconTokensExplicit || cfg.PlannerMaxInvestigationTokensExplicit {
		t.Fatalf("aggregate override changed phase limits: %+v", cfg)
	}
}

func TestPlannerTokenFlagsRejectNegative(t *testing.T) {
	streamTestEnvironment(t)
	for _, flag := range []string{"planner-max-tokens", "planner-max-recon-tokens", "planner-max-investigation-tokens"} {
		for _, command := range []string{"run", "plan"} {
			if _, err := Parse([]string{command, ".", "--" + flag + "=-1"}); err == nil || !strings.Contains(err.Error(), flag) {
				t.Fatalf("%s accepted negative %s: %v", command, flag, err)
			}
		}
	}
}
