package trustirfacts

import (
	"context"
	"strings"
	"testing"
)

// TestRun_UsesLLMRegisteredTableAndDisclosesProvenance is the end-to-end
// proof that the LLM annotation path and the deterministic knownFactTables
// path coexist through the SAME unchanged Run entry point (see
// factsource.go's doc comment): SetFactTable is the only thing that
// changes between this test and run_test.go's
// TestRun_Success_VulnerableFindsLocations, and Run's signature, inputs,
// and control flow are otherwise identical.
func TestRun_UsesLLMRegisteredTableAndDisclosesProvenance(t *testing.T) {
	t.Cleanup(ResetFactTables)

	repo, commit := localRepo(t)
	SetFactTable(repo, FactTable{
		ClaimProducers:      []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
		RollbackFields:      []string{"version"},
		ProducedStructs:     []string{"shdr_pub_key"},
		RollbackAuthorities: []RollbackAuthorityFact{{Function: "check_update_version", Kind: "state_restore_acceptance"}},
	})

	eng := &fakeEngine{available: true}
	req := Request{
		RunDir: t.TempDir(), Repository: repo, Commit: commit,
		Operation: OperationRollbackVersionPropagation, QueryPackDir: checkedInQueryPackDir(t),
	}
	fact, err := Run(context.Background(), eng, req)
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
// other half of "both must coexist": absent any SetFactTable call, Run
// behaves exactly as the pre-existing deterministic skeleton did.
func TestRun_FallsBackToDeterministicFixtureWhenNoLLMTableRegistered(t *testing.T) {
	t.Cleanup(ResetFactTables)

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
	fact, err := Run(context.Background(), eng, req)
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
