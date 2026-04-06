package pipeline_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestPipelineHeuristic(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()
	knowledgeRoot := filepath.Join(outputDir, "knowledge")

	cfg := config.Config{
		Command:       "run",
		Target:        filepath.Join(root, "testdata", "sample_repo"),
		Mode:          "heuristic",
		Focus:         "runtime",
		RunID:         "pipeline-test-001",
		OutputDir:     outputDir,
		KnowledgeRoot: knowledgeRoot,
		MaxHotspots:   4,
		MaxCases:      4,
		StaticTools:   "auto",
	}

	runDir, err := pipeline.Run(cfg)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	for _, path := range []string{
		runfs.ProjectProfilePath(runDir),
		runfs.GraphPath(runDir),
		runfs.ArbiterFindingsPath(runDir),
	} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected artifact %s: %v", path, statErr)
		}
	}
}
