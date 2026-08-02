package pipeline_test

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
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
