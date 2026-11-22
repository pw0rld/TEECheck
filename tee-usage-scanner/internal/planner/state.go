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
	RunID           string                      `json:"run_id"`
	Rounds          []artifacts.RoundRecord     `json:"rounds"`
	Candidates      []artifacts.Candidate       `json:"candidates"`
	AuditLeads      []artifacts.AuditLead       `json:"audit_leads,omitempty"`
	Contracts       []artifacts.CaseInvariantV2 `json:"contracts,omitempty"`
	PreScannedTaint *PreScannedTaint            `json:"pre_scanned_taint,omitempty"`
	SinksSeen       []artifacts.SinkHitGroup    `json:"sinks_seen,omitempty"`

	// Investigations holds every TWEInvestigation the Planner has built so
	// far this run (§7.5, §9.5). Each entry already carries its own
	// filled/missing roles, outstanding required evidence, counterevidence,
	// and coverage gaps — see artifacts.TWEInvestigation — so this single
	// field is what BuildRoundPrompt's "ACTIVE TWE INVESTIGATIONS" section
	// renders and what the main loop appends to as the LLM's `done` payload
	// declares new or updated investigations across passes.
	Investigations []artifacts.TWEInvestigation `json:"investigations,omitempty"`

	// PlaybookDetails holds the full text of every TWE playbook detail the
	// Planner has pulled via the twe_playbook_detail action so far this run,
	// in the order first pulled. A pulled detail otherwise reaches the LLM
	// only through BuildRoundPrompt's RECENT ROUNDS rendering, which keeps
	// only the last 2 rounds and cuts everything but the newest to
	// scrollbackBytes — so a detail block sized against the 3000-token
	// budget (see twecontext.maxDetailContextTokens) survives one round and
	// then scrolls out. Storing it here, mirroring
	// Investigations, lets BuildRoundPrompt render it in full for every
	// remaining round of the loop instead of letting it evaporate.
	PlaybookDetails []PulledPlaybookDetail `json:"playbook_details,omitempty"`
}

// PulledPlaybookDetail is one TWE's full investigation method, pulled by a
// twe_playbook_detail action during this run, kept verbatim for the rest of
// the loop.
type PulledPlaybookDetail struct {
	TWEID string `json:"twe_id"`
	Text  string `json:"text"`
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
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync rounds log: %w", err)
	}
	s.AppendRound(r)
	return nil
}

// AddCandidates appends new candidates to the state. Caller is
// responsible for de-duplication by ID if needed.
func (s *PlannerState) AddCandidates(cands []artifacts.Candidate) {
	s.Candidates = append(s.Candidates, cands...)
}

// AddInvestigations appends new TWEInvestigations to the state. Caller is
// responsible for de-duplication by InvestigationID if needed — Build's
// deterministic ID means re-adding the same investigation content produces
// the same ID, so a caller that wants "latest wins" semantics should
// dedupe by ID before calling this, mirroring AddCandidates' contract.
func (s *PlannerState) AddInvestigations(invs []artifacts.TWEInvestigation) {
	s.Investigations = append(s.Investigations, invs...)
}

// AddPlaybookDetail stores a pulled TWE playbook detail under tweID,
// preserving first-pull insertion order for stable prompt rendering. A
// second pull of the same tweID is a no-op — the detail text for a given id
// is stable within a run, so there is nothing to update and no reason to
// store it twice.
func (s *PlannerState) AddPlaybookDetail(tweID, text string) {
	for _, d := range s.PlaybookDetails {
		if d.TWEID == tweID {
			return
		}
	}
	s.PlaybookDetails = append(s.PlaybookDetails, PulledPlaybookDetail{TWEID: tweID, Text: text})
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
