package pipeline

import (
	"errors"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
)

// captureRecorder collects emitted events in memory, assigning seq the
// same way JSONLRecorder does so ordering assertions are meaningful.
type captureRecorder struct {
	events []events.Event
}

func (c *captureRecorder) Emit(e events.Event) error {
	e.Seq = int64(len(c.events) + 1)
	e.Time = time.Now()
	c.events = append(c.events, e)
	return nil
}

func (c *captureRecorder) Close() error { return nil }

func TestRunStage_EmitsStartedAndCompleted(t *testing.T) {
	rec := &captureRecorder{}
	ran := false

	err := runStage(rec, "run-1", "preprocess", func() error {
		ran = true
		return nil
	})
	if err != nil {
		t.Fatalf("runStage returned %v, want nil", err)
	}
	if !ran {
		t.Fatal("the stage body did not run")
	}
	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2: %+v", len(rec.events), rec.events)
	}

	started, completed := rec.events[0], rec.events[1]
	if started.Type != events.TypeStageStarted {
		t.Errorf("events[0].Type=%q want %q", started.Type, events.TypeStageStarted)
	}
	if completed.Type != events.TypeStageCompleted {
		t.Errorf("events[1].Type=%q want %q", completed.Type, events.TypeStageCompleted)
	}
	for i, e := range rec.events {
		if e.Stage != "preprocess" {
			t.Errorf("events[%d].Stage=%q want preprocess", i, e.Stage)
		}
		if e.RunID != "run-1" {
			t.Errorf("events[%d].RunID=%q want run-1", i, e.RunID)
		}
		if e.Seq != int64(i+1) {
			t.Errorf("events[%d].Seq=%d want %d", i, e.Seq, i+1)
		}
	}
	if completed.Reason != "completed" {
		t.Errorf("completed.Reason=%q want completed", completed.Reason)
	}
	if completed.Error != "" {
		t.Errorf("completed.Error=%q want empty", completed.Error)
	}
	if completed.DurationMs < 0 {
		t.Errorf("completed.DurationMs=%d", completed.DurationMs)
	}
}

// TestRunStage_FailingStageStillEmitsCompleted is the case the record
// matters most for: a stream that goes silent on failure tells you
// nothing about where the run died.
func TestRunStage_FailingStageStillEmitsCompleted(t *testing.T) {
	rec := &captureRecorder{}
	sentinel := errors.New("architecture: malformed reply")

	err := runStage(rec, "run-1", "architecture", func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("runStage must return the stage's error unchanged, got %v", err)
	}
	if len(rec.events) != 2 {
		t.Fatalf("emitted %d events, want 2 (started + completed) even on failure", len(rec.events))
	}
	completed := rec.events[1]
	if completed.Type != events.TypeStageCompleted {
		t.Fatalf("events[1].Type=%q want %q", completed.Type, events.TypeStageCompleted)
	}
	if completed.Reason != "error" {
		t.Errorf("completed.Reason=%q want error", completed.Reason)
	}
	if completed.Error != sentinel.Error() {
		t.Errorf("completed.Error=%q want %q", completed.Error, sentinel.Error())
	}
	if completed.Stage != "architecture" {
		t.Errorf("completed.Stage=%q want architecture", completed.Stage)
	}
}

// TestRunStage_NilRecorderStillRunsStage: instrumentation must never be
// the reason a stage does not run.
func TestRunStage_NilRecorderStillRunsStage(t *testing.T) {
	ran := false
	if err := runStage(nil, "run-1", "preprocess", func() error { ran = true; return nil }); err != nil {
		t.Fatalf("err=%v", err)
	}
	if !ran {
		t.Fatal("stage body did not run with a nil recorder")
	}
}

// TestRunStage_OrderingIsStartedThenBodyThenCompleted pins the bracket:
// the started event must precede any event the stage body itself emits,
// and the completed event must follow all of them.
func TestRunStage_OrderingIsStartedThenBodyThenCompleted(t *testing.T) {
	rec := &captureRecorder{}
	_ = runStage(rec, "run-1", "expert", func() error {
		return rec.Emit(events.ClaimEmitted("run-1", "expert-001", "case-001", "c1", "claim", nil))
	})
	if len(rec.events) != 3 {
		t.Fatalf("emitted %d events, want 3", len(rec.events))
	}
	want := []string{events.TypeStageStarted, events.TypeClaimEmitted, events.TypeStageCompleted}
	for i, w := range want {
		if rec.events[i].Type != w {
			t.Errorf("events[%d].Type=%q want %q", i, rec.events[i].Type, w)
		}
		if rec.events[i].Seq != int64(i+1) {
			t.Errorf("events[%d].Seq=%d want %d", i, rec.events[i].Seq, i+1)
		}
	}
}
