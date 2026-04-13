package planner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// PlannerState is the working memory of the L3 planner across rounds.
//
// It is structured (not an append-only transcript) to keep the LLM
// prompt size bounded: each round's prompt is built from a snapshot
// of this state, not by replaying the full history. Full history is
// persisted to rounds.jsonl on disk for debugging and post-hoc
// analysis but is not fed back to the LLM.
type PlannerState struct {
	RunID      string                   `json:"run_id"`
	Rounds     []artifacts.RoundRecord  `json:"rounds"`
	Candidates []artifacts.Candidate    `json:"candidates"`
	SinksSeen  []artifacts.SinkHitGroup `json:"sinks_seen,omitempty"`
}

// NewState returns an empty PlannerState bound to a run id.
func NewState(runID string) *PlannerState {
	return &PlannerState{
		RunID: runID,
	}
}

// AppendRound appends a round record to in-memory state. Use
// AppendRoundAndPersist to also write to the rounds.jsonl log.
func (s *PlannerState) AppendRound(r artifacts.RoundRecord) {
	s.Rounds = append(s.Rounds, r)
}

// AppendRoundAndPersist appends the round to in-memory state AND
// writes one JSONL line to logPath. The file is created if missing
// and appended to (not overwritten) on subsequent calls. The parent
// directory is created if missing.
func (s *PlannerState) AppendRoundAndPersist(r artifacts.RoundRecord, logPath string) error {
	s.AppendRound(r)

	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for rounds log: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open rounds log: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal round: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write rounds log: %w", err)
	}
	return nil
}

// AddCandidates appends new candidates to the state. Caller is
// responsible for de-duplication by ID if needed.
func (s *PlannerState) AddCandidates(cands []artifacts.Candidate) {
	s.Candidates = append(s.Candidates, cands...)
}

// LastRoundsForPrompt returns up to n most recent rounds for prompt
// assembly. The full Rounds slice is not fed to the LLM — only this
// trailing window keeps the prompt size bounded.
func (s *PlannerState) LastRoundsForPrompt(n int) []artifacts.RoundRecord {
	if n <= 0 || len(s.Rounds) == 0 {
		return nil
	}
	if len(s.Rounds) <= n {
		out := make([]artifacts.RoundRecord, len(s.Rounds))
		copy(out, s.Rounds)
		return out
	}
	out := make([]artifacts.RoundRecord, n)
	copy(out, s.Rounds[len(s.Rounds)-n:])
	return out
}
