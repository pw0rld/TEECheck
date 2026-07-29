package pipeline

import (
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
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

// enrichCasesWithRepomix is the legacy-mode repomix wiring. npx is present
// in this image, so a stand-in npx lets this run end to end.
func TestEnrichCasesWithRepomix_RecordsThroughExecutor(t *testing.T) {
	eventstest.FakeBinary(t, "npx", `
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then OUT="$a"; fi
  prev="$a"
done
cat > "$OUT" <<'BODY'
{"files":{"src/a.rs":"fn main() {}\n"}}
BODY
`)

	runDir := t.TempDir()
	if err := runfs.WriteJSON(
		filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"),
		artifacts.CasePack{CaseID: "c-001", TargetFiles: []string{"src/a.rs"}},
	); err != nil {
		t.Fatal(err)
	}

	h := eventstest.New(t)
	exec := executor.Bind(&executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs},
		executor.Binding{RunID: "run-7", Agent: "repomix-enrich"})

	enrichCasesWithRepomix(runDir, t.TempDir(), exec)

	started, completed := h.ToolEvents(h.Events(), 0)
	if started.ToolName != "repomix" {
		t.Errorf("tool_name = %q, want repomix", started.ToolName)
	}
	if started.RunID != "run-7" || started.Agent != "repomix-enrich" {
		t.Errorf("run_id/agent = %q/%q, want run-7/repomix-enrich", started.RunID, started.Agent)
	}
	if !completed.ToolOK {
		t.Errorf("tool_ok = false: %+v", completed)
	}

	// And the enrichment still did its job.
	var pack artifacts.CasePack
	if err := runfs.ReadJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), &pack); err != nil {
		t.Fatal(err)
	}
	if len(pack.Snippets) != 1 || pack.Snippets[0].Path != "src/a.rs" {
		t.Errorf("snippets = %+v, want the repomix content spliced in", pack.Snippets)
	}
}

// With no executor the enrichment must still work and record nothing.
func TestEnrichCasesWithRepomix_NoExecutorRecordsNothing(t *testing.T) {
	eventstest.FakeBinary(t, "npx", `
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then OUT="$a"; fi
  prev="$a"
done
cat > "$OUT" <<'BODY'
{"files":{"src/a.rs":"fn main() {}\n"}}
BODY
`)

	runDir := t.TempDir()
	if err := runfs.WriteJSON(
		filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"),
		artifacts.CasePack{CaseID: "c-001", TargetFiles: []string{"src/a.rs"}},
	); err != nil {
		t.Fatal(err)
	}
	h := eventstest.New(t)

	enrichCasesWithRepomix(runDir, t.TempDir(), nil)

	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", e.Type)
		}
	}
	var pack artifacts.CasePack
	if err := runfs.ReadJSON(filepath.Join(runfs.CasePacksDir(runDir), "case-001.json"), &pack); err != nil {
		t.Fatal(err)
	}
	if len(pack.Snippets) != 1 {
		t.Errorf("enrichment did not run without an executor: %+v", pack.Snippets)
	}
}
