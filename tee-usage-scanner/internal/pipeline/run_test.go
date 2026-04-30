package pipeline_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
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

	// V1.1.2 polish C4 regression: pipeline must persist
	// role-based AgentIDs (expert-001, verifier-001, arbiter-001),
	// not the legacy tool identities (scanner-001, reviewer-001,
	// auditor-001) it used pre-polish.
	expectAgentID(t, runDir, "04_expert/hypothesis-001.json", "expert-001",
		func(b []byte) (string, error) {
			var h artifacts.Hypothesis
			if err := json.Unmarshal(b, &h); err != nil {
				return "", err
			}
			return h.AgentID, nil
		})
	expectAgentID(t, runDir, "06_verifier/verify-001.json", "verifier-001",
		func(b []byte) (string, error) {
			var m artifacts.VerificationMemo
			if err := json.Unmarshal(b, &m); err != nil {
				return "", err
			}
			return m.AgentID, nil
		})
}

// expectAgentID reads a per-stage JSON artifact under runDir and
// asserts its agent_id matches want. Skips silently if the file is
// missing (heuristic mode may not produce a file when there are
// zero hypotheses) — assertion only fires when the file exists.
func expectAgentID(t *testing.T, runDir, rel, want string, parse func([]byte) (string, error)) {
	t.Helper()
	path := filepath.Join(runDir, rel)
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("skip agent_id check on %s (file absent)", rel)
			return
		}
		t.Fatalf("read %s: %v", path, err)
	}
	got, err := parse(body)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if got != want {
		t.Errorf("%s agent_id = %q, want %q (role-based AgentID regression)", rel, got, want)
	}
}
