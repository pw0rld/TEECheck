package pipeline

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

type unavailablePrescanEngine struct{ calls int }

func (*unavailablePrescanEngine) Available() bool { return false }
func (e *unavailablePrescanEngine) Analyze(context.Context, codeql.AnalyzeOptions) ([]codeql.Result, error) {
	e.calls++
	return nil, nil
}

func TestEntryTaintPrescanUnavailableRemainsNonblockingAndPersisted(t *testing.T) {
	repo, runDir := setupPlannerRun(t, "source.c")
	engine := &unavailablePrescanEngine{}
	got := runEntryTaintPrescan(config.Config{KnowledgeRoot: t.TempDir()}, engine, nil, runDir, repo)
	if got == nil || len(got.CoverageGaps) == 0 || engine.calls != 0 {
		t.Fatalf("unsupported prescan did not retain gap: %+v calls=%d", got, engine.calls)
	}
	if got.FactRef != "" {
		t.Fatal("unsupported fact was presented as a successful clue")
	}
	saved, err := loadPrescanContext(runDir)
	if err != nil || !reflect.DeepEqual(saved, got) {
		t.Fatalf("snapshot=%+v err=%v", saved, err)
	}
}

func TestPrescanContextSnapshotRoundTripAndMalformedRejection(t *testing.T) {
	runDir := t.TempDir()
	if got, err := loadPrescanContext(runDir); err != nil || got != nil {
		t.Fatalf("missing old-run snapshot=%+v %v", got, err)
	}
	input := &planner.PreScannedTaint{FactRef: "/run/fact.json", Summary: "deterministic clue, not a verdict", CoverageGaps: []string{"not a runtime reachability proof"}}
	if err := writeResumeJSON(prescanContextPath(runDir), prescanContextSnapshot{SchemaVersion: prescanContextSchema, Context: input}); err != nil {
		t.Fatal(err)
	}
	got, err := loadPrescanContext(runDir)
	if err != nil || !reflect.DeepEqual(input, got) {
		t.Fatalf("snapshot=%+v %v", got, err)
	}
	if err := os.WriteFile(prescanContextPath(runDir), []byte(`{"schema_version":"wrong","context":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrescanContext(runDir); err == nil {
		t.Fatal("wrong schema accepted")
	}
}

func TestConfiguredPlannerWallClockExplicitZero(t *testing.T) {
	for _, tc := range []struct {
		cfg  config.Config
		want time.Duration
	}{
		{config.Config{}, 10 * time.Minute},
		{config.Config{PlannerWallClockExplicit: true}, 0},
		{config.Config{PlannerWallClock: 40 * time.Minute}, 40 * time.Minute},
	} {
		b := configuredPlannerBudget(tc.cfg)
		if b.WallClock != tc.want || b.MaxRounds != 8 || b.MaxReconRounds != 10 {
			t.Fatalf("budget=%+v", b)
		}
	}
}

func TestResumeSettingsBindDisabledPlannerClock(t *testing.T) {
	cfg := config.Config{KnowledgeRoot: t.TempDir()}
	roles, err := cfg.ResolveRoleConfigs()
	if err != nil {
		t.Fatal(err)
	}
	before, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PlannerWallClockExplicit = true
	after, err := resolvedResumeSettings(cfg, roles)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(before, after) || after.Budget.WallClock != 0 {
		t.Fatal("resume fingerprint ignored disabled clock")
	}
}
