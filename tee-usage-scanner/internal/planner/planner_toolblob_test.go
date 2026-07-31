package planner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// resolveBlob reads the body a "sha256:<hex>" ref points at. Tests assert
// on the resolved CONTENT — a non-empty ref proves nothing.
func resolveBlob(t *testing.T, runDir, ref string) string {
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

func findEvent(t *testing.T, es []events.Event, typ, tool string) events.Event {
	t.Helper()
	for _, e := range es {
		if e.Type == typ && e.ToolName == tool {
			return e
		}
	}
	t.Fatalf("no %s event for tool %q found in %v", typ, tool, eventTypes(es))
	return events.Event{}
}

// TestPlannerRun_InProcessToolRecordsArgsAndFullOutput is the regression
// test for the in-process half of the tool-call recording gap. A planner
// read_file used to leave only {"tool_name":"read_file","tool_ok":true} —
// so which file, which lines, and what came back were unrecoverable. The
// round record in rounds.jsonl truncates observations at 4000 chars, which
// is precisely how "the truncated read from round 5 didn't show lines
// 35-80" became undiagnosable. The blob must hold the UNTRUNCATED output.
func TestPlannerRun_InProcessToolRecordsArgsAndFullOutput(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	// 400 lines x ~40 chars ≈ 16 KB — comfortably past the 4000-char
	// truncation the round observation applies.
	var big strings.Builder
	for i := 1; i <= 400; i++ {
		fmt.Fprintf(&big, "line %04d: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", i)
	}
	writeRepoFile(t, repoRoot, "src/big.rs", big.String())

	readArgs := `{"path":"src/big.rs","start":1,"end":400}`
	client := &mockLLM{scripts: []string{
		`{"thought":"read","actions":[{"name":"read_file","args":` + readArgs + `}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"x","candidates":[]}}]}`,
	}}

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
		RunID:    "test-toolblob",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{Focus: "tee"},
		Client:   client,
		Registry: actions.NewDefaultRegistryWithNav(),
		Budget:   defaultTestBudget(),
		Events:   rec,
		Blobs:    blobs,
	})
	if result.Err != nil {
		t.Fatalf("planner: %v", result.Err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	es := readEventsJSONL(t, eventsPath)

	started := findEvent(t, es, events.TypeToolCallStarted, "read_file")
	if got := resolveBlob(t, runDir, started.ToolArgsBlob); got != readArgs {
		t.Errorf("args blob = %q, want the exact args the planner asked for %q", got, readArgs)
	}

	completed := findEvent(t, es, events.TypeToolCallCompleted, "read_file")
	output := resolveBlob(t, runDir, completed.ToolOutputBlob)
	if !strings.Contains(output, "line 0001:") {
		t.Errorf("output blob is missing the first line of the read")
	}
	if !strings.Contains(output, "line 0400:") {
		t.Errorf("output blob is missing the last line of the read — it was truncated")
	}
	if len(output) <= 4000 {
		t.Errorf("output blob is %d bytes; the round record truncates at 4000 so a blob "+
			"that short means the truncated copy was recorded, not the full one", len(output))
	}

	// And prove the blob really is the more complete record: the round
	// observation for the same call IS truncated.
	roundsData, err := os.ReadFile(filepath.Join(runDir, "04_planner", "rounds.jsonl"))
	if err != nil {
		t.Fatalf("read rounds.jsonl: %v", err)
	}
	if len(roundsData) == 0 {
		t.Fatal("rounds.jsonl empty")
	}
	var round1 struct {
		Observations []struct {
			Output string `json:"output"`
		} `json:"observations"`
	}
	line1 := strings.SplitN(strings.TrimRight(string(roundsData), "\n"), "\n", 2)[0]
	if err := json.Unmarshal([]byte(line1), &round1); err != nil {
		t.Fatalf("unmarshal round 1: %v", err)
	}
	if len(round1.Observations) != 1 {
		t.Fatalf("round 1 observations = %d, want 1", len(round1.Observations))
	}
	if len(round1.Observations[0].Output) >= len(output) {
		t.Errorf("round observation (%d bytes) is not shorter than the blob (%d bytes) — "+
			"this test no longer proves the blob adds anything",
			len(round1.Observations[0].Output), len(output))
	}
}

// failingHandler is an in-process action that fails AFTER producing
// output — the shape a real tool takes when it partially succeeds then
// errors. Both halves must reach the event stream.
type failingHandler struct{}

func (failingHandler) Name() string { return "flaky_tool" }

func (failingHandler) Run(context.Context, actions.ActionRequest) actions.ActionResult {
	return actions.ActionResult{
		Name:   "flaky_tool",
		OK:     false,
		Output: "partial output produced before the failure",
		Error:  "flaky_tool: exploded on the second pass",
	}
}

// TestPlannerRun_FailedToolRecordsOutputAndError: a tool that errored is
// exactly the call someone will be diagnosing, so its output must not be
// dropped on the failure path.
func TestPlannerRun_FailedToolRecordsOutputAndError(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	flakyArgs := `{"why":"because"}`
	client := &mockLLM{scripts: []string{
		`{"thought":"try","actions":[{"name":"flaky_tool","args":` + flakyArgs + `}]}`,
		`{"thought":"done","actions":[{"name":"done","args":{"summary":"x","candidates":[]}}]}`,
	}}

	reg := actions.NewDefaultRegistryWithNav()
	reg.Register(failingHandler{})

	eventsPath := filepath.Join(runDir, "events.jsonl")
	rec, err := events.NewJSONLRecorder(eventsPath)
	if err != nil {
		t.Fatalf("rec: %v", err)
	}
	blobs, err := events.NewBlobStore(filepath.Join(runDir, "blobs"))
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}

	planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-toolfail",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{Focus: "tee"},
		Client:   client,
		Registry: reg,
		Budget:   defaultTestBudget(),
		Events:   rec,
		Blobs:    blobs,
	})
	rec.Close()

	es := readEventsJSONL(t, eventsPath)

	started := findEvent(t, es, events.TypeToolCallStarted, "flaky_tool")
	if got := resolveBlob(t, runDir, started.ToolArgsBlob); got != flakyArgs {
		t.Errorf("args blob = %q, want %q", got, flakyArgs)
	}

	completed := findEvent(t, es, events.TypeToolCallCompleted, "flaky_tool")
	if completed.ToolOK {
		t.Error("ToolOK=true on a failing tool")
	}
	if !strings.Contains(completed.Error, "exploded") {
		t.Errorf("Error=%q, want the handler's error", completed.Error)
	}
	if got, want := resolveBlob(t, runDir, completed.ToolOutputBlob),
		"partial output produced before the failure"; got != want {
		t.Errorf("output blob on the failure path = %q, want %q", got, want)
	}
}
