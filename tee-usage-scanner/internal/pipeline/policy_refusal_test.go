package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

func TestRunL3Planner_PolicyRefusalStopsEvenWithDeterministicCases(t *testing.T) {
	root, run := setupPlannerRun(t, "src/a.c")
	original := deterministicCasesFn
	t.Cleanup(func() { deterministicCasesFn = original })
	deterministicCasesFn = func(context.Context, trustirfacts.Engine, codedb.DatabaseProvider, string, string, string, string, string, string) ([]artifacts.CasePack, error) {
		return []artifacts.CasePack{{CaseID: "deterministic:preserved", TargetFiles: []string{"src/a.c"}}}, nil
	}
	client := &llmtest.FakeClient{Err: errors.New("upstream status 502: flagged for possible cybersecurity risk")}
	err := runL3Planner(config.Config{Focus: "tee", RunDir: run, KnowledgeRoot: t.TempDir(), Samples: 2}, client, nil, root, run, events.Nop{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "policy refusal") {
		t.Fatalf("policy refusal must be terminal: %v", err)
	}
	if len(client.Calls) != 1 {
		t.Fatalf("refusal sent to additional model calls: %d", len(client.Calls))
	}
}

func TestMergeEvidenceBundles_PreservesCoverageGaps(t *testing.T) {
	merged := MergeEvidenceBundles([]*artifacts.EvidenceBundle{
		{CoverageGaps: []string{"first gap"}},
		{CoverageGaps: []string{"first gap", "second gap"}},
	})
	if len(merged.CoverageGaps) != 2 || merged.CoverageGaps[1] != "second gap" {
		t.Fatalf("coverage gaps lost or duplicated: %v", merged.CoverageGaps)
	}
}
