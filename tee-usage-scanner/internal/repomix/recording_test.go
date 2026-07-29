package repomix

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

func TestRecordsArgsAndOutput(t *testing.T) {
	fakeNPX(t, samplePack, 0)
	h := eventstest.New(t)

	res, err := Pack(context.Background(), PackRequest{
		RepoRoot:    "/repo/root",
		TargetFiles: []string{"src/a.rs"},
		Compress:    true,
		Exec:        &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs},
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if res.Files["src/a.rs"] == "" {
		t.Fatalf("files = %#v", res.Files)
	}

	started, completed := h.ToolEvents(h.Events(), 0)
	if started.ToolName != "repomix" {
		t.Errorf("tool_name = %q, want repomix", started.ToolName)
	}
	args := strings.Split(h.Blob(started.ToolArgsBlob), "\n")
	want := []string{"repomix", "/repo/root", "--style", "json", "--compress", "--include", "src/a.rs", "-o"}
	if len(args) != len(want)+1 {
		t.Fatalf("args blob lines = %q, want %d + the temp -o target", args, len(want))
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
	if !strings.Contains(args[len(args)-1], "repomix-") {
		t.Errorf("-o target not recorded: %q", args[len(args)-1])
	}
	if !completed.ToolOK {
		t.Error("tool_ok = false, want true")
	}
}

// A failing npx must record its output and its error.
func TestRecordsFailingSubprocess(t *testing.T) {
	eventstest.FakeBinary(t, "npx", `echo "npm ERR! not found" >&2; exit 1`)
	h := eventstest.New(t)

	_, err := Pack(context.Background(), PackRequest{
		RepoRoot: "/repo",
		Exec:     &executor.LocalExecutor{Recorder: h.Recorder, Blobs: h.Blobs},
	})
	if err == nil {
		t.Fatal("expected an error")
	}

	_, completed := h.ToolEvents(h.Events(), 0)
	if completed.ToolOK {
		t.Error("tool_ok = true on a failing subprocess")
	}
	if completed.ToolExitCode != 1 {
		t.Errorf("tool_exit_code = %d, want 1", completed.ToolExitCode)
	}
	if got := h.Blob(completed.ToolStderrBlob); strings.TrimSpace(got) != "npm ERR! not found" {
		t.Errorf("stderr blob = %q", got)
	}
}

func TestNoExecutorStillWorksAndRecordsNothing(t *testing.T) {
	fakeNPX(t, samplePack, 0)
	h := eventstest.New(t)

	if _, err := Pack(context.Background(), PackRequest{RepoRoot: "/repo"}); err != nil {
		t.Fatalf("Pack without executor: %v", err)
	}
	for _, e := range h.Events() {
		if e.Type == events.TypeToolCallStarted || e.Type == events.TypeToolCallCompleted {
			t.Fatalf("recorded %s with no executor wired", e.Type)
		}
	}
}
