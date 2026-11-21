package pipeline_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestPipelineResumePreservesRunAndStageHistory(t *testing.T) {
	cfg := probeConfig(t, "llm")
	cfg.EnableLegacyPrior = false
	failed := &llmtest.FakeClient{Err: errors.New("test connection stopped")}
	runDir, err := pipeline.RunWithClient(cfg, failed)
	if err == nil {
		t.Fatal("expected interrupted planner")
	}
	before, err := os.ReadFile(runfs.ManifestPath(runDir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(runDir, "04_planner", "state.json")); err != nil {
		t.Fatal(err)
	}
	cfg.Resume, cfg.RunDir = true, runDir
	fake := &llmtest.FakeClient{Default: plannerDoneJSON}
	got, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got != runDir {
		t.Fatalf("created another run: %s", got)
	}
	after, err := os.ReadFile(runfs.ManifestPath(runDir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("resume rewrote original provenance")
	}
	all := readEvents(t, runDir)
	var starts, ends int
	for _, e := range all {
		if e.Type == events.TypeRunStarted {
			starts++
		}
		if e.Type == events.TypeRunCompleted {
			ends++
		}
	}
	if starts != 1 || ends != 1 {
		t.Fatalf("run events %d/%d", starts, ends)
	}
	for stage, es := range stageIndex(all) {
		if len(es) != 2 {
			t.Fatalf("stage %s has %d events", stage, len(es))
		}
	}
	archives, _ := filepath.Glob(filepath.Join(runDir, "04_planner", "resume-history", "*.tar"))
	if len(archives) != 1 {
		t.Fatalf("archives: %v", archives)
	}
}

func TestPipelineResumeRejectsChangedSourceWithoutChangingJournal(t *testing.T) {
	cfg := probeConfig(t, "llm")
	cfg.EnableLegacyPrior = false
	runDir, err := pipeline.RunWithClient(cfg, &llmtest.FakeClient{Err: errors.New("test interrupted")})
	if err == nil {
		t.Fatal("expected interruption")
	}
	journal := filepath.Join(runDir, "events.jsonl")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cfg.Target, "previously-unread.c"), []byte("int changed;"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Resume, cfg.RunDir = true, runDir
	fake := &llmtest.FakeClient{Default: plannerDoneJSON}
	_, err = pipeline.RunWithClient(cfg, fake)
	if err == nil || !strings.Contains(err.Error(), "source tree content changed") {
		t.Fatalf("wrong rejection: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatal("called model on changed source")
	}
	after, _ := os.ReadFile(journal)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected resume modified journal")
	}
}

func TestPipelineResumeRejectsChangedSettings(t *testing.T) {
	cfg := probeConfig(t, "llm")
	cfg.EnableLegacyPrior = false
	runDir, err := pipeline.RunWithClient(cfg, &llmtest.FakeClient{Err: errors.New("interrupted")})
	if err == nil {
		t.Fatal("expected interruption")
	}
	cfg.Resume, cfg.RunDir = true, runDir
	cfg.LLMModel = "different-model"
	fake := &llmtest.FakeClient{Default: plannerDoneJSON}
	_, err = pipeline.RunWithClient(cfg, fake)
	if err == nil || !strings.Contains(err.Error(), "configuration or knowledge changed") {
		t.Fatalf("wrong rejection: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatal("called changed model")
	}
}
