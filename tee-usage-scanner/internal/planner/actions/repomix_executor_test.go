package actions_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// fakeNPXForAction installs an npx stand-in that writes a minimal repomix
// report to the -o target. The real `repomix` npm package is not installed
// here and invoking it would reach the npm registry.
func fakeNPXForAction(t *testing.T) {
	t.Helper()
	eventstest.FakeBinary(t, "npx", `
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then OUT="$a"; fi
  prev="$a"
done
cat > "$OUT" <<'BODY'
{"files":{"a.rs":"fn verify_quote() {}\n"}}
BODY
`)
}

// The repomix_summarize action takes its executor from the ActionRequest
// the planner already populates. If that stops being threaded through, the
// npx subprocess goes back to being invisible.
func TestRepomixSummarize_RecordsThroughActionExecutor(t *testing.T) {
	fakeNPXForAction(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn verify_quote() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := eventstest.New(t)

	res := actions.RepomixSummarizeHandler{}.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, ".", false),
		RepoRoot: dir,
		Executor: &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs},
		RunID:    "run-11",
		Agent:    "planner-001",
		Round:    2,
	})
	if !res.OK {
		t.Fatalf("action failed: %+v", res)
	}

	started, completed := h.ToolEvents(h.Events(), 0)
	if started.ToolName != "repomix" {
		t.Errorf("tool_name = %q, want repomix", started.ToolName)
	}
	if started.RunID != "run-11" || started.Agent != "planner-001" || started.Round != 2 {
		t.Errorf("correlation = run=%q agent=%q round=%d, want run-11/planner-001/2",
			started.RunID, started.Agent, started.Round)
	}
	if !completed.ToolOK {
		t.Errorf("tool_ok = false: %+v", completed)
	}
	// The argv blob must resolve to the real command, with the resolved
	// absolute path the handler passed rather than the LLM's relative one.
	args := h.Blob(started.ToolArgsBlob)
	if !hasPrefix(args, "repomix\n"+dir+"\n--style\njson\n") {
		t.Errorf("args blob = %q, want the resolved repo root", args)
	}
}

// Unlike ripgrep, this handler must NOT refuse a nil executor: repomix has
// to keep working for callers with no event stream.
func TestRepomixSummarize_NoExecutorStillRunsAndRecordsNothing(t *testing.T) {
	fakeNPXForAction(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rs"), []byte("fn verify_quote() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := eventstest.New(t)

	res := actions.RepomixSummarizeHandler{}.Run(context.Background(), actions.ActionRequest{
		Name:     "repomix_summarize",
		Args:     repomixArgs(t, ".", false),
		RepoRoot: dir,
		// Executor deliberately nil.
	})
	if !res.OK {
		t.Fatalf("action refused to run without an executor: %+v", res)
	}
	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", e.Type)
		}
	}
}
