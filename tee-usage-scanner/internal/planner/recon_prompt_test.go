package planner

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func TestReconPromptAdvertisesTaintButNotLeadMutationActions(t *testing.T) {
	prompt := BuildSystemPrompt([]string{"trace_taint", ActionUpdateLead, ActionFormalizeContract, ActionCloseLead}, "", PriorKnowledge{}, PhaseReconnaissance)
	if !strings.Contains(prompt, "  - trace_taint  args=") {
		t.Fatal("reconnaissance must advertise tracing")
	}
	for _, name := range []string{ActionUpdateLead, ActionFormalizeContract, ActionCloseLead} {
		if strings.Contains(prompt, "  - "+name+"  args=") {
			t.Fatalf("lead-only action %s was exposed before investigation", name)
		}
	}
}

func TestReconPromptSuggestsEvidenceWorkAtBudgetCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name                string
		rounds, tokens      int
		phaseB, lead, basic bool
		want                bool
	}{
		{name: "early"},
		{name: "half rounds", rounds: 5, want: true},
		{name: "half tokens", tokens: 50000, want: true},
		{name: "basic observations", basic: true, want: true},
		{name: "already investigating", rounds: 5, phaseB: true},
		{name: "already has lead", rounds: 5, lead: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			budget := NewDefaultBudget()
			budget.ReconRoundsUsed = test.rounds
			budget.ReconTokensUsed = test.tokens
			r := NewReconState(ReconModeTreeOnly).WithTotals(1, 1, 1)
			if test.basic {
				r.Observe("get_repository_card", "", true)
				r.Observe("list_dir", ".", true)
				r.Observe("read_file", "entry.c", true)
				if !r.Satisfied() {
					t.Fatal("test did not satisfy basic observations")
				}
			}
			if test.phaseB {
				r.OpenedLead()
			}
			state := NewState("test")
			if test.lead {
				state.AuditLeads = []artifacts.AuditLead{{LeadID: "lead"}}
			}
			prompt := BuildRoundPrompt(state, PromptProfile{}, budget, nil, r)
			if strings.Contains(prompt, "RECON CHECKPOINT") != test.want {
				t.Fatalf("unexpected checkpoint presence: %s", prompt)
			}
			if test.want && (!strings.Contains(prompt, "trace_taint") || !strings.Contains(prompt, "Do not invent a lead")) {
				t.Fatal("checkpoint lost evidence or non-fabrication guidance")
			}
		})
	}
}
