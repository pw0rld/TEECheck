package semgrep

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

// Given a recording executor, one semgrep call leaves a tool_call_started /
// tool_call_completed pair whose blob refs resolve to the EXACT argv the
// adapter built and the EXACT bytes semgrep wrote.
func TestRecordsArgsAndOutput(t *testing.T) {
	fakeSemgrep(t, sampleJSON, 0)
	h := eventstest.New(t)

	a := NewWithExecutor(&executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs})
	findings, err := a.Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot:    "/repo/root",
		TargetFiles: []string{"src/a.rs"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}

	started, completed := h.ToolEvents(h.Events(), 0)

	if started.ToolName != "semgrep" {
		t.Errorf("tool_name = %q, want semgrep", started.ToolName)
	}
	wantArgs := strings.Join([]string{
		"--json", "--no-git-ignore", "--config=auto", "--include=src/a.rs", "/repo/root",
	}, "\n")
	if got := h.Blob(started.ToolArgsBlob); got != wantArgs {
		t.Errorf("args blob =\n%q\nwant\n%q", got, wantArgs)
	}
	if !completed.ToolOK {
		t.Error("tool_ok = false, want true")
	}
	if got := h.Blob(completed.ToolOutputBlob); strings.TrimSpace(got) != sampleJSON {
		t.Errorf("stdout blob =\n%q\nwant\n%q", got, sampleJSON)
	}
	if completed.Truncated {
		t.Error("truncated = true on a tiny output")
	}
}

// A failing subprocess must record both its output and its error — that is
// the call someone will be diagnosing.
func TestRecordsFailingSubprocess(t *testing.T) {
	eventstest.FakeBinary(t, "semgrep", `echo "why it died" >&2; exit 2`)
	h := eventstest.New(t)

	a := NewWithExecutor(&executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs})
	if _, err := a.Run(context.Background(), staticcheck.CheckRequest{RepoRoot: "/repo"}); err == nil {
		t.Fatal("expected an error")
	}

	_, completed := h.ToolEvents(h.Events(), 0)
	if completed.ToolOK {
		t.Error("tool_ok = true on a failing subprocess")
	}
	if completed.ToolExitCode != 2 {
		t.Errorf("tool_exit_code = %d, want 2", completed.ToolExitCode)
	}
	if got := h.Blob(completed.ToolStderrBlob); strings.TrimSpace(got) != "why it died" {
		t.Errorf("stderr blob = %q", got)
	}
}

// No executor supplied: the adapter must still work, and must record
// nothing. Instrumentation is never the reason a call fails.
func TestNoExecutorStillWorksAndRecordsNothing(t *testing.T) {
	fakeSemgrep(t, sampleJSON, 0)
	h := eventstest.New(t)

	findings, err := New().Run(context.Background(), staticcheck.CheckRequest{RepoRoot: "/repo"})
	if err != nil {
		t.Fatalf("Run without executor: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", e.Type)
		}
	}
}

// Truncation must never be silent. semgrep's stdout IS the result, so a
// truncated stream cannot be parsed as if it were whole: the adapter must
// refuse, and the record must say so.
func TestTruncatedOutputIsRefusedAndRecorded(t *testing.T) {
	// Lower the cap rather than generate 64 MiB, so the real capBuffer in
	// LocalExecutor still does the truncating and the real event still
	// carries the flag.
	restore := semgrepMaxOutputBytes
	semgrepMaxOutputBytes = 4096
	t.Cleanup(func() { semgrepMaxOutputBytes = restore })

	eventstest.FakeBinary(t, "semgrep", `head -c 1048576 /dev/zero | tr '\0' 'x'`)
	h := eventstest.New(t)

	a := NewWithExecutor(&executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs})
	_, err := a.Run(context.Background(), staticcheck.CheckRequest{RepoRoot: "/repo"})
	if err == nil {
		t.Fatal("expected an error: a truncated JSON document must not be parsed")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("err = %q, want it to name truncation", err)
	}

	_, completed := h.ToolEvents(h.Events(), 0)
	if !completed.Truncated {
		t.Error("truncated = false on the event; a shortened record must say so")
	}
}

// The registry constructor is the wiring seam the pipeline uses.
func TestConstructorsSetExecutor(t *testing.T) {
	if NewWithExecutor(&executor.LocalExecutor{}).Exec == nil {
		t.Error("NewWithExecutor did not set Exec")
	}
	if New().Exec != nil {
		t.Error("New() must leave Exec nil (non-recording default)")
	}
}
