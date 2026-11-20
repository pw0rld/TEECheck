package runinit

import (
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestRunRecordsRequiredExecutionPlan(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		dir, err := Run(config.Config{Command: "init-run", RunID: "plan", OutputDir: t.TempDir(), EnableLegacyPrior: legacy}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		m, err := runfs.LoadManifest(dir)
		if err != nil {
			t.Fatal(err)
		}
		stages := map[string]bool{}
		for _, s := range m.ExpectedStages {
			stages[s] = true
		}
		for _, s := range []string{"preprocess", "repo_index", "project_map", "l3_planner", "cases_enrich", "expert", "challenger", "verifier", "arbiter"} {
			if !stages[s] {
				t.Errorf("missing required stage %s", s)
			}
		}
		if stages["architecture"] != legacy || stages["invariants"] != legacy {
			t.Fatalf("legacy stage plan does not match configured policy: %+v", m.ExpectedStages)
		}
		if m.SourceScopeMode != "local_fallback" {
			t.Fatalf("unresolved source mode=%q", m.SourceScopeMode)
		}
	}
}
