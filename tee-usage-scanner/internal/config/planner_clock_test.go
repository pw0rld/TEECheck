package config

import (
	"testing"
	"time"
)

func TestPlannerWallClockExplicitZero(t *testing.T) {
	streamTestEnvironment(t)
	for _, command := range []string{"run", "plan"} {
		for _, tc := range []struct {
			name     string
			flags    []string
			want     time.Duration
			explicit bool
		}{
			{"omitted", nil, 0, false},
			{"disabled", []string{"--planner-wall-clock", "0"}, 0, true},
			{"positive", []string{"--planner-wall-clock=40m"}, 40 * time.Minute, true},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				cfg, err := Parse(append([]string{command, "."}, tc.flags...))
				if err != nil {
					t.Fatal(err)
				}
				if cfg.PlannerWallClock != tc.want || cfg.PlannerWallClockExplicit != tc.explicit {
					t.Fatalf("clock=%s explicit=%v", cfg.PlannerWallClock, cfg.PlannerWallClockExplicit)
				}
			})
		}
	}
	if _, err := Parse([]string{"run", ".", "--planner-wall-clock=-1s"}); err == nil {
		t.Fatal("negative clock accepted")
	}
}
