package pipeline_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

// readEvents parses every line of a run's events.jsonl.
func readEvents(t *testing.T, runDir string) []events.Event {
	t.Helper()
	f, err := os.Open(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		t.Fatalf("open events.jsonl: %v", err)
	}
	defer f.Close()

	var out []events.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse events.jsonl line %q: %v", line, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan events.jsonl: %v", err)
	}
	return out
}

// TestPipeline_RecordsLLMCallsPerAgent is the regression test for the
// diagnosability gap: before the recording decorator, a stage that failed
// on a malformed reply left nothing in events.jsonl and nothing in blobs/,
// so the reply that broke it was unrecoverable. Every LLM-backed stage the
// pipeline drives must now leave an llm_call_completed attributed to that
// stage's agent id, with blob refs that resolve to the real bodies.
func TestPipeline_RecordsLLMCallsPerAgent(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()

	cfg := config.Config{
		Command:       "run",
		Target:        filepath.Join(root, "testdata", "sample_repo"),
		Mode:          "llm",
		Focus:         "runtime",
		RunID:         "pipeline-record-001",
		OutputDir:     outputDir,
		KnowledgeRoot: filepath.Join(outputDir, "knowledge"),
		LLMModel:      "fake-model-1",
		MaxHotspots:   4,
		MaxCases:      4,
		StaticTools:   "auto",
	}

	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	all := readEvents(t, runDir)
	completed := map[string][]events.Event{}
	started := map[string]int{}
	for _, e := range all {
		switch e.Type {
		case events.TypeLLMCallCompleted:
			completed[e.Agent] = append(completed[e.Agent], e)
		case events.TypeLLMCallStarted:
			started[e.Agent]++
		}
	}

	// The two stages that always issue an LLM call in llm mode. Their
	// calls used to vanish entirely.
	for _, agent := range []string{"architecture-001", "invariants-001"} {
		evs := completed[agent]
		if len(evs) != 1 {
			t.Fatalf("llm_call_completed for %s = %d, want 1 (agents seen: %v)", agent, len(evs), agentIDs(completed))
		}
		if started[agent] != 1 {
			t.Errorf("llm_call_started for %s = %d, want 1", agent, started[agent])
		}
		e := evs[0]
		if e.Model != "fake-model-1" {
			t.Errorf("%s Model = %q, want fake-model-1", agent, e.Model)
		}
		if e.Round != 0 {
			t.Errorf("%s Round = %d, want 0 — only the planner has rounds", agent, e.Round)
		}
		if e.TokensIn == 0 || e.TokensOut == 0 {
			t.Errorf("%s tokens = (%d,%d), want non-zero estimates", agent, e.TokensIn, e.TokensOut)
		}
		if e.PromptBlob == "" || e.ResponseBlob == "" {
			t.Fatalf("%s blob refs empty: prompt=%q response=%q", agent, e.PromptBlob, e.ResponseBlob)
		}
		if got := blobBody(t, runDir, e.ResponseBlob); got == "" {
			t.Errorf("%s response blob is empty", agent)
		}
		if got := blobBody(t, runDir, e.PromptBlob); got == "" {
			t.Errorf("%s prompt blob is empty", agent)
		}
	}

	// The architecture stage's response blob must hold the exact reply the
	// fake produced — that is what makes a parse failure diagnosable.
	if got := blobBody(t, runDir, completed["architecture-001"][0].ResponseBlob); got != archWireJSON {
		t.Errorf("architecture-001 response blob does not match the reply that was returned:\ngot:  %q\nwant: %q", got, archWireJSON)
	}

	// The planner records itself and must NOT be wrapped: exactly one
	// completed event per planner LLM call, never two.
	plannerEvents := completed[planner.DefaultPlannerAgentID]
	if len(plannerEvents) == 0 {
		t.Fatalf("no llm_call_completed for %s", planner.DefaultPlannerAgentID)
	}
	if started[planner.DefaultPlannerAgentID] != len(plannerEvents) {
		t.Errorf("planner started=%d completed=%d — events are not paired 1:1",
			started[planner.DefaultPlannerAgentID], len(plannerEvents))
	}
	for _, e := range plannerEvents {
		if e.Round == 0 {
			t.Errorf("planner llm_call_completed has Round 0 — the decorator recorded it, so the call is recorded twice")
		}
	}

	// Whole-file check: total llm_call_completed must equal the number of
	// Generate calls the fake actually served. A double-recorded client
	// would double this count.
	totalCompleted := 0
	for _, evs := range completed {
		totalCompleted += len(evs)
	}
	if totalCompleted != len(fake.Calls) {
		t.Errorf("llm_call_completed total = %d, but the fake served %d Generate calls — events are duplicated or missing",
			totalCompleted, len(fake.Calls))
	}
}

func agentIDs(m map[string][]events.Event) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func blobBody(t *testing.T, runDir, ref string) string {
	t.Helper()
	if !strings.HasPrefix(ref, "sha256:") {
		t.Fatalf("blob ref %q is not a sha256 reference", ref)
	}
	body, err := os.ReadFile(filepath.Join(runDir, "blobs", strings.TrimPrefix(ref, "sha256:")+".txt"))
	if err != nil {
		t.Fatalf("read blob %s: %v", ref, err)
	}
	return string(body)
}
