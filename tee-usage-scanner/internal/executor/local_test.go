package executor

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// We rely on /bin/sh + standard tools that are present everywhere
// our CI runs (Linux only). If we ever target Windows these tests
// need a build tag or a portable fixture.

func TestLocalExecutor_HappyPath(t *testing.T) {
	exec := &LocalExecutor{}
	res := exec.Run(context.Background(), Request{
		Name:    "echo",
		Command: "/bin/sh",
		Args:    []string{"-c", "echo hello"},
	})
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit=%d want 0", res.ExitCode)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello" {
		t.Errorf("stdout=%q want hello", got)
	}
	if res.DurationMs < 0 {
		t.Errorf("duration=%d", res.DurationMs)
	}
}

func TestLocalExecutor_NonZeroExit(t *testing.T) {
	exec := &LocalExecutor{}
	res := exec.Run(context.Background(), Request{
		Command: "/bin/sh",
		Args:    []string{"-c", "exit 7"},
	})
	if res.OK {
		t.Errorf("expected not OK")
	}
	if res.ExitCode != 7 {
		t.Errorf("exit=%d want 7", res.ExitCode)
	}
	if !strings.Contains(res.Error, "exit 7") {
		t.Errorf("error=%q want contains 'exit 7'", res.Error)
	}
}

func TestLocalExecutor_Timeout(t *testing.T) {
	exec := &LocalExecutor{}
	start := time.Now()
	res := exec.Run(context.Background(), Request{
		Command: "/bin/sh",
		Args:    []string{"-c", "sleep 5"},
		Profile: Profile{Timeout: 200 * time.Millisecond},
	})
	dur := time.Since(start)
	if res.OK {
		t.Error("expected timeout to mark not ok")
	}
	if !strings.Contains(res.Error, "timeout") {
		t.Errorf("error=%q want timeout", res.Error)
	}
	if dur > 2*time.Second {
		t.Errorf("real duration %v — timeout did not fire promptly", dur)
	}
}

func TestLocalExecutor_OutputCap(t *testing.T) {
	exec := &LocalExecutor{}
	// Print 1000 'A's; cap stdout at 100 bytes.
	res := exec.Run(context.Background(), Request{
		Command: "/bin/sh",
		Args:    []string{"-c", "printf 'A%.0s' $(seq 1 1000)"},
		Profile: Profile{MaxOutputBytes: 100},
	})
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}
	if len(res.Stdout) != 100 {
		t.Errorf("stdout len=%d want 100", len(res.Stdout))
	}
	if !res.Truncated {
		t.Error("Truncated=false, want true")
	}
}

func TestLocalExecutor_BinaryNotFound(t *testing.T) {
	exec := &LocalExecutor{}
	res := exec.Run(context.Background(), Request{
		Command: "/this/binary/definitely/does/not/exist",
	})
	if res.OK {
		t.Error("expected not OK")
	}
	if !strings.Contains(res.Error, "not found") &&
		!strings.Contains(res.Error, "no such") {
		t.Errorf("error=%q want 'not found' or 'no such'", res.Error)
	}
}

func TestLocalExecutor_EmptyCommand(t *testing.T) {
	exec := &LocalExecutor{}
	res := exec.Run(context.Background(), Request{Name: "noop"})
	if res.OK {
		t.Error("expected not OK")
	}
	if !strings.Contains(res.Error, "empty command") {
		t.Errorf("error=%q", res.Error)
	}
}

// captureRecorder collects emitted events in memory for assertion.
type captureRecorder struct {
	events []events.Event
}

func (c *captureRecorder) Emit(e events.Event) error {
	// Recorder normally fills in seq+time; simulate it for tests.
	e.Seq = int64(len(c.events) + 1)
	e.Time = time.Now()
	c.events = append(c.events, e)
	return nil
}

func (c *captureRecorder) Close() error { return nil }

func TestLocalExecutor_EmitsToolCallEvents(t *testing.T) {
	rec := &captureRecorder{}
	bs, err := events.NewBlobStore(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	exec := &LocalExecutor{Recorder: rec, Blobs: bs}

	res := exec.Run(context.Background(), Request{
		RunID:   "test-run",
		Agent:   "planner-001",
		Round:   3,
		Name:    "ripgrep",
		Command: "/bin/sh",
		Args:    []string{"-c", "echo found"},
	})
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(rec.events))
	}
	if rec.events[0].Type != events.TypeToolCallStarted {
		t.Errorf("events[0].Type=%q want %q", rec.events[0].Type, events.TypeToolCallStarted)
	}
	if rec.events[1].Type != events.TypeToolCallCompleted {
		t.Errorf("events[1].Type=%q want %q", rec.events[1].Type, events.TypeToolCallCompleted)
	}
	if rec.events[0].ToolName != "ripgrep" {
		t.Errorf("tool_name=%q want ripgrep", rec.events[0].ToolName)
	}
	if rec.events[0].Round != 3 {
		t.Errorf("round=%d want 3", rec.events[0].Round)
	}
	if !strings.HasPrefix(rec.events[0].ToolArgsBlob, "sha256:") {
		t.Errorf("ToolArgsBlob=%q want sha256: prefix", rec.events[0].ToolArgsBlob)
	}
	if !rec.events[1].ToolOK {
		t.Error("completed.ToolOK=false")
	}
	if rec.events[1].ToolDurationMs < 0 {
		t.Errorf("duration=%d", rec.events[1].ToolDurationMs)
	}
}

func TestLocalExecutor_EmitsCompletedOnTimeout(t *testing.T) {
	rec := &captureRecorder{}
	exec := &LocalExecutor{Recorder: rec}

	exec.Run(context.Background(), Request{
		RunID:   "r",
		Agent:   "planner-001",
		Name:    "slow",
		Command: "/bin/sh",
		Args:    []string{"-c", "sleep 2"},
		Profile: Profile{Timeout: 100 * time.Millisecond},
	})

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d, want 2", len(rec.events))
	}
	completed := rec.events[1]
	if completed.ToolOK {
		t.Error("ToolOK=true on timeout")
	}
	if !strings.Contains(completed.Error, "timeout") {
		t.Errorf("completed.Error=%q want timeout", completed.Error)
	}
}

func TestLocalExecutor_EnvAllowlist(t *testing.T) {
	exec := &LocalExecutor{}
	// Env not in allowlist → not visible to child.
	t.Setenv("TEECHECK_TEST_HIDDEN", "secret")
	t.Setenv("TEECHECK_TEST_VISIBLE", "ok")
	res := exec.Run(context.Background(), Request{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo HIDDEN=$TEECHECK_TEST_HIDDEN VISIBLE=$TEECHECK_TEST_VISIBLE"},
		Profile: Profile{EnvAllowlist: []string{"TEECHECK_TEST_VISIBLE"}},
	})
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}
	out := strings.TrimSpace(string(res.Stdout))
	if !strings.Contains(out, "HIDDEN= ") && !strings.HasSuffix(out, "HIDDEN=") &&
		!strings.Contains(out, "HIDDEN=\n") {
		// "HIDDEN=" with empty value, then a space, then VISIBLE=ok.
		// Some shells render slightly differently; accept any form
		// as long as the secret is empty.
		if strings.Contains(out, "HIDDEN=secret") {
			t.Errorf("hidden env leaked: %q", out)
		}
	}
	if !strings.Contains(out, "VISIBLE=ok") {
		t.Errorf("allowlisted env missing: %q", out)
	}
}

// _ avoids "unused" warnings if the file is opened in isolation.
var _ = events.Nop{}
