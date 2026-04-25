package planner_test

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestLoopDetector_AcceptsFirst(t *testing.T) {
	d := planner.NewLoopDetector()
	if d.ShouldReject("list_dir", `{"path":"."}`) {
		t.Fatal("first invocation should not be rejected")
	}
}

func TestLoopDetector_RejectsThirdRepetition(t *testing.T) {
	d := planner.NewLoopDetector()
	args := `{"path":"."}`

	if d.ShouldReject("list_dir", args) {
		t.Fatal("call 1 should not be rejected")
	}
	d.Record("list_dir", args)

	if d.ShouldReject("list_dir", args) {
		t.Fatal("call 2 should not be rejected")
	}
	d.Record("list_dir", args)

	if !d.ShouldReject("list_dir", args) {
		t.Fatal("call 3 should be rejected")
	}
}

func TestLoopDetector_DifferentArgsResetCounter(t *testing.T) {
	d := planner.NewLoopDetector()

	d.Record("list_dir", `{"path":"a"}`)
	d.Record("list_dir", `{"path":"a"}`)

	if d.ShouldReject("list_dir", `{"path":"b"}`) {
		t.Fatal("different args should not be rejected even after 2 prior calls")
	}
}

func TestLoopDetector_DifferentActionResetsCounter(t *testing.T) {
	d := planner.NewLoopDetector()
	args := `{"path":"."}`

	d.Record("list_dir", args)
	d.Record("list_dir", args)

	if d.ShouldReject("read_file", args) {
		t.Fatal("different action should not be rejected")
	}
}

func TestLoopDetector_StallDetector(t *testing.T) {
	s := planner.NewStallDetector()

	s.RecordRound(0)
	if s.Stalled() {
		t.Fatal("first round should not stall")
	}

	s.RecordRound(0)
	if s.Stalled() {
		t.Fatal("second round (1 unchanged) should not stall")
	}

	s.RecordRound(0)
	if !s.Stalled() {
		t.Fatal("third round (2 consecutive unchanged) should stall")
	}
}

func TestLoopDetector_StallResetOnChange(t *testing.T) {
	s := planner.NewStallDetector()
	s.RecordRound(0)
	s.RecordRound(0)
	s.RecordRound(5)
	s.RecordRound(5)
	if s.Stalled() {
		t.Fatal("stall should reset when candidate count changed")
	}
}
