package planner_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

func readEventsJSONL(t *testing.T, path string) []events.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open events: %v", err)
	}
	defer f.Close()
	var out []events.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e events.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func eventTypes(es []events.Event) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Type
	}
	return out
}

func TestPlannerRun_EmitsTypedEvents(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"ripgrep","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"x","candidates":[{"id":"c1","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["no nonce"],"confidence":0.8}]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	eventsPath := filepath.Join(runDir, "events.jsonl")
	rec, err := events.NewJSONLRecorder(eventsPath)
	if err != nil {
		t.Fatalf("rec: %v", err)
	}
	blobs, err := events.NewBlobStore(filepath.Join(runDir, "blobs"))
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}

	// Production-faithful wiring: the same recorder + blob store
	// flow into both the planner (for in-process events) and the
	// executor (for ripgrep). Ripgrep is now executor-backed, so
	// without this the planner would skip its manual emit AND the
	// handler would fail with "executor not provided".
	exec := &executor.LocalExecutor{Recorder: rec, Blobs: blobs}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:       "test-events",
		RepoRoot:    repoRoot,
		RunDir:      runDir,
		Profile:     planner.PromptProfile{Focus: "tee", Languages: []string{"rust"}},
		Client:      client,
		Registry:    reg,
		Budget:      defaultTestBudget(),
		Temperature: 0,
		Events:      rec,
		Blobs:       blobs,
		Model:       "glm-4.7",
		Executor:    exec,
	})
	if result.Err != nil {
		t.Fatalf("planner: %v", result.Err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	es := readEventsJSONL(t, eventsPath)
	if len(es) == 0 {
		t.Fatal("no events recorded")
	}

	// Seq monotonic, starts at 1.
	for i, e := range es {
		want := int64(i + 1)
		if e.Seq != want {
			t.Errorf("events[%d].Seq = %d, want %d", i, e.Seq, want)
		}
	}

	// Verify the expected event sequence for a 2-round happy path.
	// Round 1: round_started, llm_started, llm_completed, tool_started, tool_completed, round_completed
	// Round 2: same shape but with done as the tool — done emits started/completed too.
	wantTypes := []string{
		events.TypePlannerRoundStarted,
		events.TypeLLMCallStarted,
		events.TypeLLMCallCompleted,
		events.TypeToolCallStarted,
		events.TypeToolCallCompleted,
		events.TypePlannerRoundCompleted,
		events.TypePlannerRoundStarted,
		events.TypeLLMCallStarted,
		events.TypeLLMCallCompleted,
		events.TypeToolCallStarted,
		events.TypeToolCallCompleted,
		events.TypePlannerRoundCompleted,
	}
	gotTypes := eventTypes(es)
	if len(gotTypes) != len(wantTypes) {
		t.Fatalf("event count = %d, want %d\nfull: %v", len(gotTypes), len(wantTypes), gotTypes)
	}
	for i := range wantTypes {
		if gotTypes[i] != wantTypes[i] {
			t.Errorf("events[%d].Type = %q, want %q", i, gotTypes[i], wantTypes[i])
		}
	}

	// LLM event payload sanity: model carried through, tokens recorded
	// (mock LLM returns no usage, so falls back to char/4 estimate >0).
	for _, e := range es {
		if e.Type == events.TypeLLMCallCompleted {
			if e.Model != "glm-4.7" {
				t.Errorf("llm_call_completed Model = %q, want glm-4.7", e.Model)
			}
			if e.TokensIn == 0 || e.TokensOut == 0 {
				t.Errorf("llm_call_completed tokens = (%d,%d), want both > 0", e.TokensIn, e.TokensOut)
			}
			if !strings.HasPrefix(e.PromptBlob, "sha256:") {
				t.Errorf("llm_call_completed PromptBlob = %q, want sha256: prefix", e.PromptBlob)
			}
			if !strings.HasPrefix(e.ResponseBlob, "sha256:") {
				t.Errorf("llm_call_completed ResponseBlob = %q, want sha256: prefix", e.ResponseBlob)
			}
		}
	}

	// Round numbers populate correctly.
	roundsByType := map[string][]int{}
	for _, e := range es {
		roundsByType[e.Type] = append(roundsByType[e.Type], e.Round)
	}
	if got := roundsByType[events.TypePlannerRoundStarted]; !equalInts(got, []int{1, 2}) {
		t.Errorf("planner_round_started rounds = %v, want [1 2]", got)
	}
	if got := roundsByType[events.TypePlannerRoundCompleted]; !equalInts(got, []int{1, 2}) {
		t.Errorf("planner_round_completed rounds = %v, want [1 2]", got)
	}

	// Blob store is populated.
	blobFiles, _ := os.ReadDir(filepath.Join(runDir, "blobs"))
	if len(blobFiles) == 0 {
		t.Errorf("blob store is empty; expected prompt/response/tool-args bodies")
	}

	// No-double-emit guard: round 1 dispatches ripgrep
	// (executor-backed) and round 2 dispatches done (in-process).
	// Each round must contribute exactly one tool_call_started and
	// one tool_call_completed — never two pairs for the same call.
	startedByRound := map[int]int{}
	completedByRound := map[int]int{}
	for _, e := range es {
		switch e.Type {
		case events.TypeToolCallStarted:
			startedByRound[e.Round]++
		case events.TypeToolCallCompleted:
			completedByRound[e.Round]++
		}
	}
	for round, n := range startedByRound {
		if n != 1 {
			t.Errorf("round %d: %d tool_call_started events, want 1 (double-emit?)", round, n)
		}
	}
	for round, n := range completedByRound {
		if n != 1 {
			t.Errorf("round %d: %d tool_call_completed events, want 1 (double-emit?)", round, n)
		}
	}

	// Profile metadata only on the executor-backed (ripgrep) call.
	// Round 1 = ripgrep → started event must carry network/timeout.
	// Round 2 = done    → started event must NOT carry them.
	for _, e := range es {
		if e.Type != events.TypeToolCallStarted {
			continue
		}
		if e.ToolName == "ripgrep" {
			if e.Network == "" {
				t.Error("ripgrep started event missing Network metadata")
			}
			if e.Write == "" {
				t.Error("ripgrep started event missing Write metadata")
			}
			if e.TimeoutMs == 0 {
				t.Error("ripgrep started event missing TimeoutMs")
			}
			if e.MaxOutputBytes == 0 {
				t.Error("ripgrep started event missing MaxOutputBytes")
			}
		}
		if e.ToolName == "done" {
			if e.Network != "" {
				t.Errorf("done is in-process but carries Network=%q", e.Network)
			}
		}
	}

	// Executor-backed completed event must carry tool_exit_code.
	// The ripgrep run in this test searches for "verify_quote" in
	// the fixture which contains it, so exit code is 0 (matches).
	// Hand-rolled in-process actions (done) leave it absent.
	for _, e := range es {
		if e.Type != events.TypeToolCallCompleted {
			continue
		}
		if e.ToolName == "ripgrep" {
			// exit code 0 is the happy path; the JSON omits it
			// (omitempty), so we only require the corresponding OK
			// flag and absence of an error.
			if !e.ToolOK {
				t.Errorf("ripgrep completed not OK; error=%q", e.Error)
			}
			if e.Error != "" {
				t.Errorf("ripgrep completed has Error=%q (want empty for exit 0)", e.Error)
			}
		}
	}
}

// TestPlannerRun_RipgrepNoMatchSurfacesExitCodeInEvent verifies the
// "rg exit 1 = no matches" path surfaces the non-zero exit code in
// the completed event. The happy-path test cannot exercise this
// because exit 0 is omitempty'd out of the JSON. Exit 1 is the
// scenario where downstream consumers most need to distinguish
// "tool said no" from a real failure — making sure that signal
// reaches events.jsonl is the v1 smoke we care about.
func TestPlannerRun_RipgrepNoMatchSurfacesExitCodeInEvent(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		// Search for a string that is NOT in the fixture → exit 1.
		`{"thought":"ripgrep","actions":[{"name":"ripgrep","args":{"pattern":"definitely_not_in_fixture","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"none","candidates":[{"id":"c1","kind":"attestation","priority":"low","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["nothing matched"],"confidence":0.1}]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	eventsPath := filepath.Join(runDir, "events.jsonl")
	rec, err := events.NewJSONLRecorder(eventsPath)
	if err != nil {
		t.Fatalf("rec: %v", err)
	}
	exec := &executor.LocalExecutor{Recorder: rec}

	planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-no-match",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{Focus: "tee", Languages: []string{"rust"}},
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
		Events:   rec,
		Executor: exec,
	})
	rec.Close()

	es := readEventsJSONL(t, eventsPath)
	var rgCompleted *events.Event
	for i, e := range es {
		if e.Type == events.TypeToolCallCompleted && e.ToolName == "ripgrep" {
			rgCompleted = &es[i]
			break
		}
	}
	if rgCompleted == nil {
		t.Fatal("no ripgrep tool_call_completed event found")
	}

	// rg exit 1 = no matches. The handler maps this to ActionResult
	// OK=true (a normal "no matches" outcome is not a failure), but
	// the executor's completed event records the raw exit code so
	// downstream consumers can audit what actually happened.
	if rgCompleted.ToolExitCode != 1 {
		t.Errorf("ripgrep ToolExitCode=%d, want 1 (no-match scenario)", rgCompleted.ToolExitCode)
	}
	if rgCompleted.Error != "" {
		t.Errorf("ripgrep Error=%q, want empty (clean process exit, just non-zero)", rgCompleted.Error)
	}
}

// TestPlannerRun_RipgrepFailsCleanlyWhenExecutorMissing pins the
// runtime contract for executor-backed actions: when RunConfig.Executor
// is nil and the LLM requests an executor-backed handler, the planner
// must (a) not panic, (b) record OK=false with an executor-mentioning
// error in the round observation, and (c) keep going so a later round
// can still emit done. Without this test, accidental regressions in
// the wiring (pipeline forgets to pass Executor, or a new
// executor-backed handler skips the nil-check) would only surface as
// silent FP/FN at audit time.
func TestPlannerRun_RipgrepFailsCleanlyWhenExecutorMissing(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"ripgrep","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"ok","candidates":[{"id":"c1","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["forced done"],"confidence":0.5}]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithNav()

	// Intentionally NO Executor — this is the regression scenario.
	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:       "test-no-exec",
		RepoRoot:    repoRoot,
		RunDir:      runDir,
		Profile:     planner.PromptProfile{Focus: "tee", Languages: []string{"rust"}},
		Client:      client,
		Registry:    reg,
		Budget:      defaultTestBudget(),
		Temperature: 0,
	})

	// The planner must complete without surfacing a Go error.
	if result.Err != nil {
		t.Fatalf("planner returned err = %v; expected clean completion despite missing executor", result.Err)
	}
	if result.Bundle == nil {
		t.Fatal("planner returned nil bundle")
	}
	if result.Bundle.PlannerMeta.TerminationReason != "llm_done" {
		t.Errorf("termination=%q, want llm_done (planner should still reach done)", result.Bundle.PlannerMeta.TerminationReason)
	}

	// Round 1 (ripgrep) observation must be OK=false with an
	// executor-mentioning error so the LLM can self-correct.
	roundsData, err := os.ReadFile(filepath.Join(runDir, "04_planner", "rounds.jsonl"))
	if err != nil {
		t.Fatalf("read rounds.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(roundsData), "\n"), "\n")
	if len(lines) < 1 {
		t.Fatal("rounds.jsonl is empty")
	}

	var round1 struct {
		Observations []struct {
			Name  string `json:"name"`
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &round1); err != nil {
		t.Fatalf("unmarshal round 1: %v", err)
	}
	if len(round1.Observations) != 1 {
		t.Fatalf("round 1 observations = %d, want 1", len(round1.Observations))
	}
	obs := round1.Observations[0]
	if obs.Name != "ripgrep" {
		t.Errorf("observation name = %q, want ripgrep", obs.Name)
	}
	if obs.OK {
		t.Error("ripgrep observation OK=true, want false (Executor was nil)")
	}
	if !strings.Contains(obs.Error, "executor") {
		t.Errorf("observation error = %q, want it to mention 'executor'", obs.Error)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
