package planner

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestLeadNotesRemainVisibleAfterFiveRounds(t *testing.T) {
	state := NewState("memory")
	state.AuditLeads = []artifacts.AuditLead{{RunID: "memory", LeadID: "lead-memory", State: artifacts.LeadStateExpanded, SecurityQuestion: "Which input reaches the decision?", EvidenceNotes: []artifacts.LeadEvidenceNote{{FactRef: "obs:0:1:0:read", Summary: "Early source establishes the input owner", AddedAtRound: 1}}, RuledOut: []string{"An unrelated helper does not make the decision"}, ContractIDs: []string{"case-inv-kept"}}}
	for i := 1; i <= 7; i++ {
		state.AppendRound(artifacts.RoundRecord{Round: i, Observations: []artifacts.RoundObservation{{Name: "read_file", OK: true, Output: "newer source"}}})
	}
	prompt := BuildRoundPrompt(state, PromptProfile{}, NewDefaultBudget(), nil)
	for _, want := range []string{"lead-memory", "Early source establishes the input owner", "obs:0:1:0:read", "case-inv-kept", "An unrelated helper"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("sticky lead lost %q after five rounds", want)
		}
	}
}

func TestLeadMemoryBoundsWholeRecordsAndArchivesClosedLeads(t *testing.T) {
	state := NewState("memory")
	for i := 0; i < 20; i++ {
		lead := artifacts.AuditLead{RunID: "memory", LeadID: strings.Repeat("L", 100), State: artifacts.LeadStateExpanded, SecurityQuestion: strings.Repeat("界", 400)}
		for j := 0; j < 32; j++ {
			lead.EvidenceNotes = append(lead.EvidenceNotes, artifacts.LeadEvidenceNote{FactRef: "obs:source", Summary: strings.Repeat("界", 80)})
		}
		row := compactLead(lead)
		if len(row) > 2048 || !utf8.ValidString(row) || !json.Valid([]byte(row)) || !strings.Contains(row, "omitted_items") {
			t.Fatalf("invalid bounded record: %s", row)
		}
		state.AuditLeads = append(state.AuditLeads, lead)
	}
	state.AuditLeads = append(state.AuditLeads, artifacts.AuditLead{RunID: "memory", LeadID: "closed-lead", State: artifacts.LeadStateClosed, CloseReason: "Examined the alternate path"})
	block := leadMemoryBlock(state, 8192)
	if len(block) > 8192 || !utf8.ValidString(block) || !strings.Contains(block, "additional active leads omitted") || !strings.Contains(block, "CLOSED LEADS") {
		t.Fatalf("memory block not bounded/archived: %d %s", len(block), block)
	}
}

func TestCoverageLedgerCountsClosedLeadsSeparately(t *testing.T) {
	_, run := reliabilityFixture(t)
	cfg := RunConfig{RunID: "reliable", RunDir: run}
	for _, state := range []string{artifacts.LeadStateOpen, artifacts.LeadStateClosed} {
		if err := appendAuditLead(runfs.AuditLeadsPath(run), artifacts.AuditLead{RunID: "reliable", LeadID: "lead", State: state}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeCoverageLedger(cfg, NewReconState(ReconModeTreeOnly), artifacts.ProjectMap{}, 1); err != nil {
		t.Fatal(err)
	}
	var ledger artifacts.CoverageLedger
	if err := runfs.ReadJSON(runfs.CoverageLedgerPath(run), &ledger); err != nil {
		t.Fatal(err)
	}
	if ledger.LeadsOpen != 0 || len(ledger.BySample) != 1 || ledger.BySample[0].LeadsOpened != 1 || ledger.BySample[0].LeadsClosed != 1 {
		t.Fatalf("wrong lifecycle counts: %+v", ledger)
	}
}
