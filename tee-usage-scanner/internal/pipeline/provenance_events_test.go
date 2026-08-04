package pipeline_test

import (
	"os"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func firstOfType(es []events.Event, typ string) (events.Event, bool) {
	for _, e := range es {
		if e.Type == typ {
			return e, true
		}
	}
	return events.Event{}, false
}

// A run that cannot say how it was invoked cannot be re-run. run-b's command
// line was recoverable only by inference — the manifest carried a repository
// and a commit that git could not have detected for the scanned tree, so the
// identity overrides must have been passed; the target, run-id and hint could
// not be recovered at all.
func TestPipeline_RecordsItsLaunchCommand(t *testing.T) {
	cfg := probeConfig(t, "llm")
	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	ev, ok := firstOfType(readEvents(t, runDir), events.TypeRunConfig)
	if !ok {
		t.Fatalf("no %s event — the invocation is unrecorded", events.TypeRunConfig)
	}
	if ev.Command == "" {
		t.Error("run_config carries no command")
	}
	if ev.RunID == "" {
		t.Error("run_config has no run_id")
	}
}

// run_started names the target the user typed, and must: it is emitted before
// anything is fetched. The scope is decided 59 lines later, and when a pinned
// checkout is used the two differ — run-b reported a benchmark fixture
// directory while every stage read a full optee_os checkout. Without this
// event nothing in the stream says which tree was read.
func TestPipeline_RecordsResolvedSourceScope(t *testing.T) {
	cfg := probeConfig(t, "llm")
	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	all := readEvents(t, runDir)
	ev, ok := firstOfType(all, events.TypeSourceScopeResolved)
	if !ok {
		t.Fatalf("no %s event — the scanned tree is unrecorded", events.TypeSourceScopeResolved)
	}
	if ev.Target == "" {
		t.Error("source_scope_resolved names no root")
	}
	// This probe has no pinned identity, so it must say it fell back rather
	// than leaving a reader to assume a checkout happened.
	if !strings.Contains(ev.Reason, "no pinned checkout") {
		t.Errorf("reason=%q must distinguish the fallback from a pinned checkout", ev.Reason)
	}

	// The scope must be settled before the first stage reads anything.
	scopeSeq := ev.Seq
	for _, e := range all {
		if e.Type == events.TypeStageStarted && e.Seq < scopeSeq {
			t.Errorf("stage %q started at seq %d, before the scope was resolved at seq %d",
				e.Stage, e.Seq, scopeSeq)
		}
	}
}

// The database is built once per run, by the index stage.
//
// It used to be built inside the planner's first round: 91.6 seconds of the
// planner's own budget spent on infrastructure, arriving as a round-0 tool
// call and therefore invisible as infrastructure. And with the resolution
// and build unexported inside internal/trustirfacts, a second consumer could
// only have built a second one.
func TestPipeline_BuildsTheDatabaseOnceUnderTheIndexAgent(t *testing.T) {
	cfg := probeConfig(t, "llm")
	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	byAgent := map[string]int{}
	for _, e := range readEvents(t, runDir) {
		if e.Type == events.TypeToolCallStarted && e.ToolName == "codeql-database-create" {
			byAgent[e.Agent]++
		}
	}
	for agent, n := range byAgent {
		if agent == "planner-001" {
			t.Errorf("the planner built the database %d time(s) — that is 91 seconds of its own budget", n)
		}
		if n > 1 {
			t.Errorf("agent %q built the database %d times, want at most 1", agent, n)
		}
	}
	// This probe has no pinned repository, so no database is built at all.
	// The assertion that matters is the one above: whatever builds it, it is
	// not the planner and it happens at most once.
	if total := len(byAgent); total > 1 {
		t.Errorf("the database was built by %d different agents: %v", total, byAgent)
	}
}

// The index and the map are stateless with respect to each other's failures:
// both artifacts exist after a run, whatever the index could or could not do.
func TestPipeline_WritesBothIndexArtifacts(t *testing.T) {
	cfg := probeConfig(t, "llm")
	fake := &llmtest.FakeClient{
		Responses: []string{archWireJSON, invariantWireJSON, plannerDoneJSON},
		Default:   plannerDoneJSON,
	}
	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}
	for _, path := range []string{runfs.RepoFactsPath(runDir), runfs.ProjectMapPath(runDir)} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected artifact %s: %v", path, err)
		}
	}

	// This probe has no pinned repository, so the index degrades — and the
	// degradation is the assertion. An index stage that silently did nothing
	// would leave the same empty artifact as one that ran and could not
	// build, and every downstream "no callers found" inherits the
	// difference.
	var facts artifacts.RepoFacts
	if err := runfs.ReadJSON(runfs.RepoFactsPath(runDir), &facts); err != nil {
		t.Fatal(err)
	}
	if facts.IndexNote == "" {
		t.Error("a run with no pinned revision must record why it has no index")
	}
	if facts.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		t.Errorf("symbols = %q, want unavailable", facts.Capabilities.Symbols)
	}

	// The map carries that verdict forward, because it is the only thing the
	// Planner reads.
	var m artifacts.ProjectMap
	if err := runfs.ReadJSON(runfs.ProjectMapPath(runDir), &m); err != nil {
		t.Fatal(err)
	}
	if m.Capabilities.Symbols != artifacts.CapabilityUnavailable {
		t.Errorf("the map reports symbols = %q, want the index's own verdict", m.Capabilities.Symbols)
	}
	// The tree is still described: modules and sizes need no CodeQL.
	if m.Repository.FileCount == 0 {
		t.Error("the map must still describe the tree even with no index")
	}
}
