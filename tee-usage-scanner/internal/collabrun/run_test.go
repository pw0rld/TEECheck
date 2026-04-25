package collabrun

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/feedback"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/review"
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

func TestReviewAndFeedbackFlow(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()
	knowledgeRoot := filepath.Join(outputDir, "knowledge")

	cfg := config.Config{
		Command:       "collab-run",
		RunID:         "feedback-test-001",
		RepoURL:       "https://example.com/sample.git",
		LocalPath:     filepath.Join(root, "testdata", "sample_repo"),
		Commit:        "deadbeefcafebabe",
		Focus:         "runtime",
		OutputDir:     outputDir,
		KnowledgeRoot: knowledgeRoot,
		GraphJSONPath: filepath.Join(root, "testdata", "sample_graph.json"),
		MaxHotspots:   4,
		MaxCases:      4,
	}

	runDir, err := Run(cfg, time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("collab run failed: %v", err)
	}

	// Simulate interactive review (Phase 1 prompt order):
	//   verdict, [fp_reason if FP], severity_override,
	//   confidence_override, tags, notes
	//   then on next iteration: quit
	input := "t\n\n\ntee\nLooks legit\nq\n"
	var output bytes.Buffer
	reviewCfg := config.Config{
		Command:       "review",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
	}
	if err := review.RunWithIO(reviewCfg, strings.NewReader(input), &output, time.Date(2026, 4, 6, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("review failed: %v", err)
	}

	// Check review output was created
	if _, err := os.Stat(filepath.Join(runfs.ReviewDir(runDir), "review-001.json")); err != nil {
		t.Fatalf("review-001.json not found: %v", err)
	}

	// Run feedback
	var fbOutput bytes.Buffer
	fbCfg := config.Config{
		Command:       "feedback",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
	}
	if err := feedback.Run(fbCfg, &fbOutput); err != nil {
		t.Fatalf("feedback failed: %v", err)
	}

	// Check that learned/ got an archive file
	matches, _ := filepath.Glob(filepath.Join(knowledgeRoot, "learned", "*", "*.md"))
	if len(matches) == 0 {
		t.Fatal("expected at least one learned archive file")
	}
}
