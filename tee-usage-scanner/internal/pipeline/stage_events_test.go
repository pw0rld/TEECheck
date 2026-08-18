package pipeline_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func probeConfig(t *testing.T, mode string) config.Config {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	target := filepath.Join(t.TempDir(), "sample_repo")
	if err := os.CopyFS(target, os.DirFS(filepath.Join(root, "testdata", "sample_repo"))); err != nil {
		t.Fatalf("copy sample repository: %v", err)
	}
	outputDir := t.TempDir()
	return config.Config{
		Command:       "run",
		Target:        target,
		Mode:          mode,
		Focus:         "runtime",
		RunID:         "pipeline-stage-001",
		OutputDir:     outputDir,
		KnowledgeRoot: filepath.Join(outputDir, "knowledge"),
		LLMModel:      "fake-model-1",
		MaxHotspots:   4,
		MaxCases:      4,
		StaticTools:   "auto",
	}
}

// stageIndex folds an event stream into stage -> the started/completed
// events recorded for it.
func stageIndex(es []events.Event) map[string][]events.Event {
	out := map[string][]events.Event{}
	for _, e := range es {
		if e.Type == events.TypeStageStarted || e.Type == events.TypeStageCompleted {
			out[e.Stage] = append(out[e.Stage], e)
		}
	}
	return out
}

// TestPipeline_EveryStageLeavesStageEvents is the regression test for
// `grep stage_ events.jsonl` returning nothing: only stages that happened
// to make an LLM call left any trace at all, and the deterministic ones
// (profile, TWE context, cases) left none. From the stream alone you could
// not tell whether they ran, how long they took, or whether they failed.
func TestPipeline_EveryStageLeavesStageEvents(t *testing.T) {
	cfg := probeConfig(t, "llm")
	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}
	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if manifest.Configuration == nil || manifest.Configuration.Planner == nil {
		t.Fatal("completed pipeline did not record planner limits")
	}
	limits := manifest.Configuration.Planner
	if limits.MaxInvestigationRounds != 8 || limits.MaxReconRounds != 10 || limits.MaxAggregateTokens != 120000 {
		t.Fatalf("planner limits = %+v", limits)
	}

	all := readEvents(t, runDir)
	byStage := stageIndex(all)

	// The llm-mode stage set, in the order pipeline.RunWithClient drives
	// them. Deterministic stages are in here precisely because they were
	// the invisible ones.
	wantStages := []string{
		"preprocess",
		"repo_index",
		"project_map",
		"architecture",
		"invariants",
		"l3_planner",
		"cases_enrich",
		"expert",
		"challenger",
		"verifier",
		"arbiter",
	}
	for _, stage := range wantStages {
		evs := byStage[stage]
		if len(evs) != 2 {
			t.Errorf("stage %q: %d stage_* events, want 2 (started + completed); saw stages %v",
				stage, len(evs), stageNames(byStage))
			continue
		}
		if evs[0].Type != events.TypeStageStarted {
			t.Errorf("stage %q: first event is %q, want %q", stage, evs[0].Type, events.TypeStageStarted)
		}
		if evs[1].Type != events.TypeStageCompleted {
			t.Errorf("stage %q: second event is %q, want %q", stage, evs[1].Type, events.TypeStageCompleted)
		}
		if evs[1].Reason != "completed" {
			t.Errorf("stage %q: completed Reason=%q, want completed", stage, evs[1].Reason)
		}
		if evs[1].Error != "" {
			t.Errorf("stage %q: completed Error=%q, want empty", stage, evs[1].Error)
		}
		if evs[0].RunID == "" {
			t.Errorf("stage %q: started event has no run_id", stage)
		}
	}

	// Ordering and seq monotonicity across the whole stream survive the
	// new emissions.
	for i, e := range all {
		if e.Seq != int64(i+1) {
			t.Fatalf("events[%d].Seq=%d, want %d — seq is no longer monotonic", i, e.Seq, i+1)
		}
	}

	// Stage brackets must nest: run_started first, run_completed last,
	// and every stage_started must precede its own stage_completed.
	if all[0].Type != events.TypeRunStarted {
		t.Errorf("first event is %q, want run_started", all[0].Type)
	}
	if last := all[len(all)-1]; last.Type != events.TypeRunCompleted {
		t.Errorf("last event is %q, want run_completed", last.Type)
	}

	// The planner's own tool/LLM events must fall INSIDE the l3_planner
	// bracket — a stage event that does not actually bracket its stage is
	// worse than none.
	var plannerStart, plannerEnd int64
	for _, e := range all {
		if e.Stage != "l3_planner" {
			continue
		}
		if e.Type == events.TypeStageStarted {
			plannerStart = e.Seq
		} else {
			plannerEnd = e.Seq
		}
	}
	if plannerStart == 0 || plannerEnd == 0 {
		t.Fatal("no l3_planner stage bracket found")
	}
	for _, e := range all {
		if e.Type != events.TypePlannerRoundStarted {
			continue
		}
		if e.Seq < plannerStart || e.Seq > plannerEnd {
			t.Errorf("planner_round_started seq=%d falls outside the l3_planner bracket [%d,%d]",
				e.Seq, plannerStart, plannerEnd)
		}
	}
}

// TestPipeline_FailingStageStillEmitsCompleted: the run dies in the
// architecture stage. The stream must say so rather than simply stopping.
func TestPipeline_FailingStageStillEmitsCompleted(t *testing.T) {
	cfg := probeConfig(t, "llm")
	fake := &llmtest.FakeClient{Err: errors.New("provider refused the request")}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err == nil {
		t.Fatal("expected the pipeline to fail when every LLM call errors")
	}
	if runDir == "" {
		t.Fatal("no run dir returned; cannot inspect the event stream")
	}

	all := readEvents(t, runDir)
	byStage := stageIndex(all)

	// preprocess runs before any LLM call and must have completed cleanly.
	pre := byStage["preprocess"]
	if len(pre) != 2 || pre[1].Reason != "completed" {
		t.Errorf("preprocess events = %+v, want a clean started/completed pair", pre)
	}

	arch := byStage["architecture"]
	if len(arch) != 2 {
		t.Fatalf("architecture: %d stage_* events, want 2 even though it failed; saw %v",
			len(arch), stageNames(byStage))
	}
	if arch[1].Type != events.TypeStageCompleted {
		t.Fatalf("architecture second event is %q, want stage_completed", arch[1].Type)
	}
	if arch[1].Reason != "error" {
		t.Errorf("architecture completed Reason=%q, want error", arch[1].Reason)
	}
	if arch[1].Error == "" {
		t.Error("architecture completed carries no error text — the reason the run died is unrecorded")
	}

	// Stages after the failure must NOT have started.
	for _, stage := range []string{"invariants", "l3_planner", "expert", "arbiter"} {
		if len(byStage[stage]) != 0 {
			t.Errorf("stage %q emitted events although the run died earlier", stage)
		}
	}

	// run_completed still closes the stream with the error.
	last := all[len(all)-1]
	if last.Type != events.TypeRunCompleted || last.Reason != "error" {
		t.Errorf("last event = %q/%q, want run_completed/error", last.Type, last.Reason)
	}
}

func stageNames(m map[string][]events.Event) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
