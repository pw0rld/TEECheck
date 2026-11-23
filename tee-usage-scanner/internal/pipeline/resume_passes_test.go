package pipeline

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
)

type interruptedSecondPass struct {
	first string
	calls int
}

func (c *interruptedSecondPass) Generate(_ context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	if c.calls == 1 {
		return llm.GenerateResponse{Text: c.first, Raw: c.first}, nil
	}
	return llm.GenerateResponse{}, errors.New("test second pass interrupted")
}

func TestResumeMultiSampleKeepsEarlierPacks(t *testing.T) {
	repo, runDir := setupPlannerRun(t, "src/first.c", "src/second.c")
	cfg := config.Config{Focus: "tee", RunDir: runDir, KnowledgeRoot: t.TempDir(), Samples: 2, AllowUncontractedCases: true}
	first := &interruptedSecondPass{first: donePass(t, "src/first.c")}
	if err := runL3Planner(cfg, first, nil, repo, runDir, events.Nop{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	cfg.Resume = true
	second := &llmtest.FakeClient{Default: donePass(t, "src/second.c")}
	if err := runL3Planner(cfg, second, nil, repo, runDir, events.Nop{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := targetFilesOf(readWrittenPacks(t, runDir))
	if !reflect.DeepEqual(got, []string{"src/first.c", "src/second.c"}) {
		t.Fatalf("lost earlier pass: %v", got)
	}
	if len(second.Calls) != 1 {
		t.Fatalf("replayed completed pass: %d model calls", len(second.Calls))
	}
}

func TestRunDirectoryLockExcludesAnotherWriter(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockRunDirectory(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if next, err := lockRunDirectory(dir, true); err == nil {
		next()
		t.Fatal("concurrent writer accepted")
	}
}
