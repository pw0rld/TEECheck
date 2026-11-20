package pipeline_test

import (
	"os"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runvalidate"
)

func TestPipelineEndToEnd_SkipsLegacyPriorByDefault(t *testing.T) {
	cfg := probeConfig(t, "llm")
	cfg.EnableLegacyPrior = false
	fake := &llmtest.FakeClient{Default: plannerDoneJSON}
	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runfs.ArchitectureModelPath(runDir), runfs.ProjectInvariantsPath(runDir)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("disabled legacy stage produced %s (stat: %v)", path, err)
		}
	}
	for _, event := range readEvents(t, runDir) {
		if event.Type == events.TypeStageStarted && (event.Stage == "architecture" || event.Stage == "invariants") {
			t.Fatalf("disabled legacy stage ran: %s", event.Stage)
		}
		if event.Agent == "architecture-001" || event.Agent == "invariants-001" {
			t.Fatalf("disabled legacy agent was called: %s", event.Agent)
		}
	}
	if report := runvalidate.Validate(runDir); !report.Valid {
		t.Fatalf("default run failed integrity validation: %+v", report.Issues)
	}
	manifest, err := runfs.LoadManifest(runDir)
	if err != nil || manifest.Configuration == nil || manifest.Configuration.EnableLegacyPrior {
		t.Fatalf("default prior policy not recorded: %+v (err=%v)", manifest.Configuration, err)
	}
}
