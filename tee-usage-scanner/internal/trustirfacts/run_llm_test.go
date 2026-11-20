package trustirfacts

import (
	"context"
	"strings"
	"testing"
)

// Explicit annotation input and shipped fixtures share Run without a mutable
// registry or hidden dependency on another request's selected revision.
func TestRun_UsesLLMRegisteredTableAndDisclosesProvenance(t *testing.T) {

	repo, commit := localRepo(t)
	table := FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		ProducedStructs:     []string{"shdr_pub_key"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	}

	eng := &fakeEngine{available: true}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	req.FactTable = NewFactTableInput(repo, commit, table, "llm_annotated")
	fact, err := Run(context.Background(), eng, newTestDB(eng), req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusSuccess {
		t.Fatalf("Status = %q, want %q (error=%q)", fact.Status, StatusSuccess, fact.Error)
	}

	foundLLMNote := false
	for _, gap := range fact.CoverageGaps {
		if strings.Contains(gap, "LLM annotation") {
			foundLLMNote = true
		}
		if strings.Contains(gap, "hand-authored fixture") {
			t.Errorf("CoverageGaps wrongly disclose the deterministic-fixture provenance for an LLM-sourced table: %q", gap)
		}
	}
	if !foundLLMNote {
		t.Errorf("expected CoverageGaps to disclose LLM provenance, got %+v", fact.CoverageGaps)
	}
}

// TestRun_FallsBackToDeterministicFixtureWhenNoLLMTableRegistered proves the
// other half of "both must coexist": absent explicit annotation input, Run
// behaves exactly as the pre-existing deterministic skeleton did.
func TestRun_FallsBackToDeterministicFixtureWhenNoLLMTableRegistered(t *testing.T) {

	repo, commit := localRepo(t)
	withTestFactTable(t, repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	})

	eng := &fakeEngine{available: true}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, newTestDB(eng), req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fact.Status != StatusSuccess {
		t.Fatalf("Status = %q, want %q (error=%q)", fact.Status, StatusSuccess, fact.Error)
	}

	foundFixtureNote := false
	for _, gap := range fact.CoverageGaps {
		if strings.Contains(gap, "hand-authored fixture") {
			foundFixtureNote = true
		}
	}
	if !foundFixtureNote {
		t.Errorf("expected CoverageGaps to disclose deterministic-fixture provenance, got %+v", fact.CoverageGaps)
	}
}
