package planner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestPlannerState_NewIsEmpty(t *testing.T) {
	s := planner.NewState("run-001")
	if s.RunID != "run-001" {
		t.Errorf("RunID = %q, want run-001", s.RunID)
	}
	if len(s.Rounds) != 0 {
		t.Errorf("Rounds len = %d, want 0", len(s.Rounds))
	}
	if len(s.Candidates) != 0 {
		t.Errorf("Candidates len = %d, want 0", len(s.Candidates))
	}
}

func TestPlannerState_AppendRoundIncrements(t *testing.T) {
	s := planner.NewState("run-001")
	s.AppendRound(artifacts.RoundRecord{Round: 1, Thought: "first"})
	s.AppendRound(artifacts.RoundRecord{Round: 2, Thought: "second"})

	if len(s.Rounds) != 2 {
		t.Fatalf("expected 2 rounds, got %d", len(s.Rounds))
	}
	if s.Rounds[1].Thought != "second" {
		t.Errorf("got %q", s.Rounds[1].Thought)
	}
}

func TestPlannerState_AddCandidates(t *testing.T) {
	s := planner.NewState("run-001")
	s.AddCandidates([]artifacts.Candidate{
		{ID: "c1", Kind: "attestation", Priority: "high"},
	})
	if len(s.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(s.Candidates))
	}
}

func TestPlannerState_PersistRound(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rounds.jsonl")

	s := planner.NewState("run-001")
	if err := s.AppendRoundAndPersist(artifacts.RoundRecord{
		Round:   1,
		Thought: "looking around",
	}, logPath); err != nil {
		t.Fatalf("persist: %v", err)
	}

	if err := s.AppendRoundAndPersist(artifacts.RoundRecord{
		Round:   2,
		Thought: "found something",
	}, logPath); err != nil {
		t.Fatalf("persist: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in jsonl, got %d", len(lines))
	}

	var rr artifacts.RoundRecord
	if err := json.Unmarshal([]byte(lines[0]), &rr); err != nil {
		t.Fatalf("parse line 0: %v", err)
	}
	if rr.Round != 1 || rr.Thought != "looking around" {
		t.Errorf("line 0 = %+v", rr)
	}
}

func TestPlannerState_PersistAppendsNotOverwrites(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rounds.jsonl")

	s := planner.NewState("run-001")
	for i := 1; i <= 3; i++ {
		if err := s.AppendRoundAndPersist(artifacts.RoundRecord{Round: i}, logPath); err != nil {
			t.Fatal(err)
		}
	}

	data, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}
