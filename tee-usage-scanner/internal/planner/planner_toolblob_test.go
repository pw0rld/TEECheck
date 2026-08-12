package planner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
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
// round record in rounds.jsonl excerpts observations at
// observationlimits.MaxBytes, which is precisely how "the truncated read
// from round 5 didn't show lines 35-80" became undiagnosable. The blob must
// hold the UNTRUNCATED output.
//
// The size of the read is derived from that constant rather than written
// down here: a second copy of the cap would keep passing after the real one
// moved, and would then be proving nothing.
func TestPlannerRun_InProcessToolRecordsArgsAndFullOutput(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	// read_file has its own line cap, so the file is made wide rather than
	// long: 200 lines each twice the excerpt budget's per-line share.
	const lines = 200
	pad := strings.Repeat("a", 2*observationlimits.MaxBytes/lines)
	var big strings.Builder
	for i := 1; i <= lines; i++ {
		fmt.Fprintf(&big, "line %04d: %s\n", i, pad)
	}
	writeRepoFile(t, repoRoot, "src/big.rs", big.String())

	readArgs := fmt.Sprintf(`{"path":"src/big.rs","start":1,"end":%d}`, lines)
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
	if !strings.Contains(output, fmt.Sprintf("line %04d:", lines)) {
		t.Errorf("output blob is missing the last line of the read — it was truncated")
	}
	if len(output) <= observationlimits.MaxBytes {
		t.Errorf("output blob is %d bytes; the round record excerpts at %d so a blob "+
			"that short means the truncated copy was recorded, not the full one",
			len(output), observationlimits.MaxBytes)
	}

	// And prove the blob really is the more complete record: the round
	// observation for the same call IS an excerpt, says so, and names the
	// blob that holds the rest. A cut with no marker is the failure this
	// path exists to stop — the model reads a fraction of the answer with no
	// way to know the rest exists.
	obs := roundObservations(t, runDir)
	if len(obs) != 1 {
		t.Fatalf("round 1 observations = %d, want 1", len(obs))
	}
	if len(obs[0].Output) >= len(output) {
		t.Errorf("round observation (%d bytes) is not shorter than the blob (%d bytes) — "+
			"this test no longer proves the blob adds anything",
			len(obs[0].Output), len(output))
	}
	if !obs[0].Truncated {
		t.Error("an excerpted observation must report that it was cut")
	}
	if !strings.Contains(obs[0].Output, completed.ToolOutputBlob) {
		t.Errorf("the excerpt must name the blob holding the full body, got tail %q",
			obs[0].Output[max(0, len(obs[0].Output)-160):])
	}
	if obs[0].OutputBlob != completed.ToolOutputBlob {
		t.Errorf("round observation blob = %q, tool_call_completed blob = %q — "+
			"the two records of one call must point at the same body",
			obs[0].OutputBlob, completed.ToolOutputBlob)
	}
}

// roundObservations reads round 1's observations out of rounds.jsonl.
func roundObservations(t *testing.T, runDir string) []artifacts.RoundObservation {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runDir, "04_planner", "rounds.jsonl"))
	if err != nil {
		t.Fatalf("read rounds.jsonl: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("rounds.jsonl empty")
	}
	var round1 artifacts.RoundRecord
	line1 := strings.SplitN(strings.TrimRight(string(data), "\n"), "\n", 2)[0]
	if err := json.Unmarshal([]byte(line1), &round1); err != nil {
		t.Fatalf("unmarshal round 1: %v", err)
	}
	return round1.Observations
}

// The ref is what an audit lead cites. If it does not survive to
// rounds.jsonl and to the event stream identically, a citation cannot be
// checked against what the planner actually saw — and an unverifiable
// citation is the failure mode this guards against.
func TestPlannerRun_ObservationRefJoinsTheRoundsLogToTheEventStream(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)
	writeRepoFile(t, repoRoot, "src/small.rs", "fn main() {}\n")

	client := &mockLLM{scripts: []string{
		`{"thought":"read","actions":[{"name":"read_file","args":{"path":"src/small.rs"}}]}`,
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
		RunID:       "test-obsref",
		RepoRoot:    repoRoot,
		RunDir:      runDir,
		SampleIndex: 2,
		Profile:     planner.PromptProfile{Focus: "tee"},
		Client:      client,
		Registry:    actions.NewDefaultRegistryWithNav(),
		Budget:      defaultTestBudget(),
		Events:      rec,
		Blobs:       blobs,
	})
	if result.Err != nil {
		t.Fatalf("planner: %v", result.Err)
	}
	rec.Close()

	obs := roundObservations(t, runDir)
	if len(obs) != 1 || obs[0].Ref == "" {
		t.Fatalf("round 1 observations = %+v, want one carrying a ref", obs)
	}

	ev := findEvent(t, readEventsJSONL(t, eventsPath), events.TypePlannerObservationRecorded, "read_file")
	if ev.ObservationRef != obs[0].Ref {
		t.Errorf("event ref %q != rounds log ref %q", ev.ObservationRef, obs[0].Ref)
	}
	if ev.SampleIndex != 2 {
		t.Errorf("event sample_index = %d, want the pass the planner was driving (2)", ev.SampleIndex)
	}
	// Sample 2 round 1 action 0 must not be spellable as sample 0's, or two
	// --samples passes cite each other's evidence.
	if want := planner.MakeObservationRef("test-obsref", 2, 1, 0, obs[0].OutputBlob); obs[0].Ref != want {
		t.Errorf("ref = %q, want %q — the ref must carry the sample index", obs[0].Ref, want)
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

// The planner records its own LLM calls (it is deliberately not wrapped in
// the recording client, because it needs round numbers), so the wire bodies
// have to be written on this path too. On 2026-08-04 a run died on two
// consecutive non-JSON replies and the artifacts could not say what the
// provider had actually returned.
func TestPlannerRun_RecordsTheWireBodiesOfEveryLLMCall(t *testing.T) {
	repoRoot, runDir := setupFixtureRepo(t)

	client := &wireLLM{
		reply:    `{"thought":"done","actions":[{"name":"done","args":{"summary":"x","candidates":[]}}]}`,
		wireReq:  `{"model":"glm-5.2","response_format":{"type":"json_object"}}`,
		wireResp: `{"choices":[{"message":{"content":"..."},"finish_reason":"stop"}]}`,
	}

	eventsPath := filepath.Join(runDir, "events.jsonl")
	rec, err := events.NewJSONLRecorder(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := events.NewBlobStore(filepath.Join(runDir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}

	planner.Run(context.Background(), planner.RunConfig{
		RunID: "test-wire", RepoRoot: repoRoot, RunDir: runDir,
		Profile: planner.PromptProfile{Focus: "tee"},
		Client:  client, Registry: actions.NewDefaultRegistryWithNav(),
		Budget: defaultTestBudget(), Events: rec, Blobs: blobs,
	})
	rec.Close()

	var completed events.Event
	for _, e := range readEventsJSONL(t, eventsPath) {
		if e.Type == events.TypeLLMCallCompleted {
			completed = e
			break
		}
	}
	if completed.WireRequestBlob == "" || completed.WireResponseBlob == "" {
		t.Fatalf("the planner dropped the wire bodies: %+v", completed)
	}
	if got := resolveBlob(t, runDir, completed.WireRequestBlob); got != client.wireReq {
		t.Errorf("wire request = %q, want the exact bytes sent", got)
	}
	if got := resolveBlob(t, runDir, completed.WireResponseBlob); got != client.wireResp {
		t.Errorf("wire response = %q, want the exact bytes received", got)
	}
	// The readable response blob still holds the parsed reply, so the two
	// are genuinely different records rather than one written twice.
	if resolveBlob(t, runDir, completed.ResponseBlob) == client.wireResp {
		t.Error("response_blob and wire_response_blob resolved to the same body")
	}
}

// wireLLM returns a usable reply plus fixed wire bytes, so the test asserts
// on what the planner persists rather than on a provider's behaviour.
type wireLLM struct {
	reply, wireReq, wireResp string
}

func (c *wireLLM) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	return llm.GenerateResponse{
		Text: c.reply, RawRequest: c.wireReq, Raw: c.wireResp,
	}, nil
}
