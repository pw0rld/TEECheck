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
	// Error/ExitCode contract: a process that ran and exited
	// non-zero is a normal tool outcome (rg returns 1 for "no
	// matches", semgrep returns non-zero with valid JSON, etc).
	// ExitCode carries the status; Error stays empty so callers
	// can distinguish "tool said no" from "execution failed".
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
	if res.Error != "" {
		t.Errorf("error=%q want empty (process started + exited cleanly with non-zero)", res.Error)
	}
}

func TestLocalExecutor_NonZeroExitWithOutput(t *testing.T) {
	// Mirrors the rg-no-matches / semgrep-with-findings shape.
	// stdout still captured, ExitCode populated, Error empty.
	exec := &LocalExecutor{}
	res := exec.Run(context.Background(), Request{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo 'tool output'; exit 1"},
	})
	if res.OK {
		t.Error("expected not OK")
	}
	if res.ExitCode != 1 {
		t.Errorf("exit=%d want 1", res.ExitCode)
	}
	if res.Error != "" {
		t.Errorf("error=%q want empty", res.Error)
	}
	if !strings.Contains(string(res.Stdout), "tool output") {
		t.Errorf("stdout=%q lost the tool output", res.Stdout)
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
		Profile: Profile{
			Network:        NetworkNone,
			Write:          WriteRunDirOnly,
			Timeout:        15 * time.Second,
			MaxOutputBytes: 8192,
		},
	})
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2", len(rec.events))
	}
	started := rec.events[0]
	completed := rec.events[1]

	if started.Type != events.TypeToolCallStarted {
		t.Errorf("events[0].Type=%q want %q", started.Type, events.TypeToolCallStarted)
	}
	if completed.Type != events.TypeToolCallCompleted {
		t.Errorf("events[1].Type=%q want %q", completed.Type, events.TypeToolCallCompleted)
	}
	if started.ToolName != "ripgrep" {
		t.Errorf("tool_name=%q want ripgrep", started.ToolName)
	}
	if started.Round != 3 {
		t.Errorf("round=%d want 3", started.Round)
	}
	if !strings.HasPrefix(started.ToolArgsBlob, "sha256:") {
		t.Errorf("ToolArgsBlob=%q want sha256: prefix", started.ToolArgsBlob)
	}

	// Profile metadata must surface on tool_call_started.
	if started.Network != "none" {
		t.Errorf("started.Network=%q want none", started.Network)
	}
	if started.Write != "run-dir-only" {
		t.Errorf("started.Write=%q want run-dir-only", started.Write)
	}
	if started.TimeoutMs != 15000 {
		t.Errorf("started.TimeoutMs=%d want 15000", started.TimeoutMs)
	}
	if started.MaxOutputBytes != 8192 {
		t.Errorf("started.MaxOutputBytes=%d want 8192", started.MaxOutputBytes)
	}

	if !completed.ToolOK {
		t.Error("completed.ToolOK=false")
	}
	if completed.ToolDurationMs < 0 {
		t.Errorf("duration=%d", completed.ToolDurationMs)
	}
	if completed.ToolExitCode != 0 {
		t.Errorf("completed.ToolExitCode=%d want 0", completed.ToolExitCode)
	}
	if completed.Truncated {
		t.Error("completed.Truncated=true on small output")
	}
}

func TestLocalExecutor_EmitsExitCodeAndTruncatedOnCompleted(t *testing.T) {
	// rg-style exit-1 with truncated output. ExitCode and Truncated
	// flags must reach the completed event so downstream analysis
	// can distinguish "no matches" from a real failure.
	rec := &captureRecorder{}
	exec := &LocalExecutor{Recorder: rec}

	exec.Run(context.Background(), Request{
		RunID:   "r",
		Agent:   "planner-001",
		Name:    "rg",
		Command: "/bin/sh",
		Args:    []string{"-c", "printf 'A%.0s' $(seq 1 1000); exit 1"},
		Profile: Profile{MaxOutputBytes: 50},
	})

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d, want 2", len(rec.events))
	}
	completed := rec.events[1]
	if completed.ToolOK {
		t.Error("ToolOK=true on non-zero exit")
	}
	if completed.ToolExitCode != 1 {
		t.Errorf("ToolExitCode=%d want 1", completed.ToolExitCode)
	}
	if completed.Error != "" {
		t.Errorf("Error=%q want empty (process exited cleanly)", completed.Error)
	}
	if !completed.Truncated {
		t.Error("Truncated=false; expected output cap to fire")
	}
}

func TestLocalExecutor_DefaultProfileSurfacedInEvent(t *testing.T) {
	// Caller passes no profile; executor still fills started event
	// with the resolved defaults so consumers can audit what
	// actually ran.
	rec := &captureRecorder{}
	exec := &LocalExecutor{Recorder: rec}

	exec.Run(context.Background(), Request{
		RunID:   "r",
		Agent:   "planner-001",
		Name:    "echo",
		Command: "/bin/sh",
		Args:    []string{"-c", "true"},
	})

	if len(rec.events) != 2 {
		t.Fatalf("emitted %d, want 2", len(rec.events))
	}
	started := rec.events[0]
	if started.TimeoutMs != DefaultTimeout.Milliseconds() {
		t.Errorf("default timeout not surfaced: TimeoutMs=%d want %d",
			started.TimeoutMs, DefaultTimeout.Milliseconds())
	}
	if started.MaxOutputBytes != DefaultMaxOutputBytes {
		t.Errorf("default cap not surfaced: MaxOutputBytes=%d want %d",
			started.MaxOutputBytes, DefaultMaxOutputBytes)
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
