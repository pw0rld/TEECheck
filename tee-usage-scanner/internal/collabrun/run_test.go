package collabrun

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestRunProducesCollaborativeArtifacts(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()
	knowledgeRoot := filepath.Join(outputDir, "knowledge")

	cfg := config.Config{
		Command:       "collab-run",
		RunID:         "collab-test-001",
		RepoURL:       "https://example.com/sample.git",
		LocalPath:     filepath.Join(root, "testdata", "sample_repo"),
		Commit:        "deadbeefcafebabe",
		Focus:         "runtime",
		OutputDir:     outputDir,
		KnowledgeRoot: knowledgeRoot,
		GraphJSONPath: filepath.Join(root, "testdata", "sample_graph.json"),
		MaxHotspots:   8,
		MaxCases:      8,
	}

	runDir, err := Run(cfg, time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("collab run failed: %v", err)
	}

	for _, path := range []string{
		runfs.ProjectProfilePath(runDir),
		runfs.RepoMapPath(runDir),
		runfs.HotspotIndexPath(runDir),
		filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"),
		filepath.Join(runfs.ExpertDir(runDir), "hypothesis-001.json"),
		filepath.Join(runfs.ChallengerDir(runDir), "challenge-001.json"),
		filepath.Join(runfs.VerifierDir(runDir), "verify-001.json"),
		filepath.Join(runfs.ArbiterPacketsDir(runDir), "review-001.md"),
		runfs.ArbiterFindingsPath(runDir),
	} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected artifact %s: %v", path, statErr)
		}
	}
}
