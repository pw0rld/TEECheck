package trustirfacts

import "testing"

func TestSetFactTable_TakesPriorityOverDeterministicFixture(t *testing.T) {
	t.Cleanup(ResetFactTables)

	repo := "https://example.com/llm-priority-test"
	deterministic := FactTable{ClaimProducers: []ClaimProducerFact{{Function: "det_fn", Role: "security_version"}}}
	withTestFactTable(t, repo, deterministic)

	got, ok := factTableFor(repo)
	if !ok || len(got.ClaimProducers) != 1 || got.ClaimProducers[0].Function != "det_fn" {
		t.Fatalf("expected the deterministic fixture before any LLM table is registered, got %+v ok=%v", got, ok)
	}

	llmTable := FactTable{ClaimProducers: []ClaimProducerFact{{Function: "llm_fn", Role: "security_version"}}}
	SetFactTable(repo, llmTable)

	got, ok = factTableFor(repo)
	if !ok || len(got.ClaimProducers) != 1 || got.ClaimProducers[0].Function != "llm_fn" {
		t.Fatalf("expected the LLM-registered table to take priority, got %+v ok=%v", got, ok)
	}
	if !isLLMFactTable(repo) {
		t.Error("isLLMFactTable should report true once SetFactTable has registered a table for this repository")
	}
}

func TestSetFactTable_NormalizesRepositoryKey(t *testing.T) {
	t.Cleanup(ResetFactTables)

	SetFactTable("https://github.com/Some/Repo.git", FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})

	if _, ok := factTableFor("git@github.com:Some/Repo.git"); !ok {
		t.Error("SetFactTable/factTableFor must agree on normalizeRepo, same as the deterministic fixture path")
	}
}

func TestResetFactTables_ClearsRegisteredTables(t *testing.T) {
	repo := "https://example.com/reset-test"
	SetFactTable(repo, FactTable{ClaimProducers: []ClaimProducerFact{{Function: "f", Role: "security_version"}}})
	if !isLLMFactTable(repo) {
		t.Fatal("setup: expected the table to be registered before Reset")
	}

	ResetFactTables()

	if isLLMFactTable(repo) {
		t.Error("expected ResetFactTables to clear the registry")
	}
	if _, ok := factTableFor(repo); ok {
		t.Error("expected no fact table at all for an unregistered, non-fixture repository after Reset")
	}
}

func TestIsLLMFactTable_FalseForDeterministicOnlyRepository(t *testing.T) {
	t.Cleanup(ResetFactTables)
	if isLLMFactTable("https://github.com/OP-TEE/optee_os") {
		t.Error("the deterministic fixture repository must not report as LLM-sourced unless SetFactTable was called")
	}
}
