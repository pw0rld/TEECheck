package pipeline

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// These tests cover the pipeline's own wiring of the recording executor
// into the subprocess-class tools. They exist because the compiler is
// otherwise the only thing checking those lines, and nil satisfies
// executor.Executor exactly as well as a real one does.

// newFactEngine is the CodeQL wiring seam. codeql is not installed in this
// project's CI image, so this asserts the wiring rather than a real CodeQL
// event — a distinction the report states plainly.
func TestNewFactEngine_WiresRecordingExecutor(t *testing.T) {
	h := eventstest.New(t)
	exec := &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs}

	eng := newFactEngine(exec, "run-42")
	if eng.Exec == nil {
		t.Fatal("newFactEngine left the engine unwired; its CodeQL calls would leave no record")
	}

	// Drive the bound executor the engine holds and check the binding
	// actually reaches the event, which is what makes a codeql tool call
	// attributable to a run and an agent.
	eng.Exec.Run(t.Context(), executor.Request{
		Name: "probe", Command: "/bin/sh", Args: []string{"-c", "exit 0"},
	})
	started, _ := h.ToolEvents(h.Events(), 0)
	if started.RunID != "run-42" {
		t.Errorf("run_id = %q, want run-42", started.RunID)
	}
	if started.Agent != "planner-001" {
		t.Errorf("agent = %q, want planner-001 — an unattributable tool call is noise", started.Agent)
	}
}
