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
	repoRoot, runDir, catalogPath := setupFixtureRepo(t)

	client := &mockLLM{scripts: []string{
		`{"thought":"ripgrep","actions":[{"name":"ripgrep","args":{"pattern":"verify_quote","globs":["*.rs"]}}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"x","candidates":[{"id":"c1","kind":"attestation","priority":"high","paths":["src/attest.rs"],"symbols":["verify_quote"],"why_selected":["no nonce"],"confidence":0.8}]}}]}`,
	}}
	reg := actions.NewDefaultRegistryWithSinks(catalogPath)

	eventsPath := filepath.Join(runDir, "events.jsonl")
	rec, err := events.NewJSONLRecorder(eventsPath)
	if err != nil {
		t.Fatalf("rec: %v", err)
	}
	blobs, err := events.NewBlobStore(filepath.Join(runDir, "blobs"))
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}

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
