package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// blobBody resolves a "sha256:<hex>" ref against a blob directory and
// returns the stored bytes. It fails the test if the ref is malformed or
// the blob is missing — asserting on the resolved CONTENT (not merely on
// the ref being non-empty) is the whole point of these tests.
func blobBody(t *testing.T, dir, ref string) string {
	t.Helper()
	if !strings.HasPrefix(ref, "sha256:") {
		t.Fatalf("blob ref %q is not a sha256 reference", ref)
	}
	body, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(ref, "sha256:")+".txt"))
	if err != nil {
		t.Fatalf("read blob %s: %v", ref, err)
	}
	return string(body)
}

// TestLocalExecutor_RecordsArgsAndOutputBlobs is the regression test for
// the diagnosis gap: a tool_call_completed used to carry the tool's name
// and nothing else, so which file was read, which lines came back, and
// what ripgrep matched all died with the process. Both blob refs must
// resolve to the EXACT bytes that went in and came out.
func TestLocalExecutor_RecordsArgsAndOutputBlobs(t *testing.T) {
	rec := &captureRecorder{}
	blobDir := filepath.Join(t.TempDir(), "blobs")
	bs, err := events.NewBlobStore(blobDir)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	exec := &LocalExecutor{Recorder: rec, Blobs: bs}

	args := []string{"-c", "echo out-line; echo err-line >&2"}
	res := exec.Run(context.Background(), Request{
		RunID: "r", Agent: "planner-001", Round: 1,
		Name: "ripgrep", Command: "/bin/sh", Args: args,
	})
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}
	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(rec.events))
	}
	started, completed := rec.events[0], rec.events[1]

	if got, want := blobBody(t, blobDir, started.ToolArgsBlob), strings.Join(args, "\n"); got != want {
		t.Errorf("args blob = %q, want %q", got, want)
	}
	if got, want := blobBody(t, blobDir, completed.ToolOutputBlob), "out-line\n"; got != want {
		t.Errorf("stdout blob = %q, want %q", got, want)
	}
	if got, want := blobBody(t, blobDir, completed.ToolStderrBlob), "err-line\n"; got != want {
		t.Errorf("stderr blob = %q, want %q", got, want)
	}
}

// TestLocalExecutor_RecordsOutputOnFailure covers the case someone will
// actually be diagnosing: the tool died. A timeout still produced bytes
// before it was killed, and those bytes plus the error are exactly the
// evidence needed. Dropping the output here would be the worst version
// of this defect.
func TestLocalExecutor_RecordsOutputOnFailure(t *testing.T) {
	rec := &captureRecorder{}
	blobDir := filepath.Join(t.TempDir(), "blobs")
	bs, err := events.NewBlobStore(blobDir)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	exec := &LocalExecutor{Recorder: rec, Blobs: bs}

	exec.Run(context.Background(), Request{
		RunID: "r", Agent: "planner-001",
		Name: "slow", Command: "/bin/sh",
		Args:    []string{"-c", "echo partial-before-death; sleep 5"},
		Profile: Profile{Timeout: 250 * time.Millisecond},
	})

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(rec.events))
	}
	completed := rec.events[1]
	if completed.ToolOK {
		t.Error("ToolOK=true on timeout")
	}
	if !strings.Contains(completed.Error, "timeout") {
		t.Errorf("Error=%q, want a timeout error", completed.Error)
	}
	if got, want := blobBody(t, blobDir, completed.ToolOutputBlob), "partial-before-death\n"; got != want {
		t.Errorf("stdout blob on failure = %q, want %q", got, want)
	}
}

// TestLocalExecutor_ExitFailureRecordsBothStreams pins the other failure
// shape: the process ran and exited non-zero after writing to both
// streams. stderr is where a tool explains itself, so it must survive.
func TestLocalExecutor_ExitFailureRecordsBothStreams(t *testing.T) {
	rec := &captureRecorder{}
	blobDir := filepath.Join(t.TempDir(), "blobs")
	bs, err := events.NewBlobStore(blobDir)
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	exec := &LocalExecutor{Recorder: rec, Blobs: bs}

	exec.Run(context.Background(), Request{
		RunID: "r", Agent: "planner-001",
		Name: "semgrep", Command: "/bin/sh",
		Args: []string{"-c", "echo stdout-said-this; echo stderr-explained-why >&2; exit 3"},
	})

	completed := rec.events[1]
	if completed.ToolExitCode != 3 {
		t.Errorf("ToolExitCode=%d want 3", completed.ToolExitCode)
	}
	if got, want := blobBody(t, blobDir, completed.ToolOutputBlob), "stdout-said-this\n"; got != want {
		t.Errorf("stdout blob = %q, want %q", got, want)
	}
	if got, want := blobBody(t, blobDir, completed.ToolStderrBlob), "stderr-explained-why\n"; got != want {
		t.Errorf("stderr blob = %q, want %q", got, want)
	}
}

// TestLocalExecutor_NoBlobStoreStillEmits guards the "instrumentation
// must never fail a run" rule: with no blob store wired the executor
// still emits both events, just without refs.
func TestLocalExecutor_NoBlobStoreStillEmits(t *testing.T) {
	rec := &captureRecorder{}
	exec := &LocalExecutor{Recorder: rec} // Blobs deliberately nil

	exec.Run(context.Background(), Request{
		RunID: "r", Agent: "planner-001",
		Name: "echo", Command: "/bin/sh", Args: []string{"-c", "echo hi"},
	})
	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(rec.events))
	}
	if rec.events[1].ToolOutputBlob != "" {
		t.Errorf("ToolOutputBlob=%q, want empty with no blob store", rec.events[1].ToolOutputBlob)
	}
}
