package trustirfacts

import "testing"

func TestFactTableInputCopiesAndScopesValues(t *testing.T) {
	table := FactTable{RollbackFields: []string{"version"}}
	input := NewFactTableInput("https://example.invalid/repo", "aaa", table, "llm_annotated")
	table.RollbackFields[0] = "mutated"
	req := Request{Repository: input.Repository, Commit: "aaa", FactTable: input}
	got, source, ok, err := req.resolveFactTable()
	if err != nil || !ok || source != "llm_annotated" || got.RollbackFields[0] != "version" {
		t.Fatalf("incorrect scoped input: %+v %s %v %v", got, source, ok, err)
	}
	got.RollbackFields[0] = "also mutated"
	again, _, _, _ := req.resolveFactTable()
	if again.RollbackFields[0] != "version" {
		t.Fatal("returned table aliases immutable request input")
	}
	req.Commit = "bbb"
	if _, _, _, err := req.resolveFactTable(); err == nil {
		t.Fatal("wrong-commit input accepted")
	}
}

func TestFactTableInputOverridesFixtureOnlyForThatRequest(t *testing.T) {
	repo := "https://github.com/OP-TEE/optee_os"
	req := Request{Repository: repo, Commit: "aaa", FactTable: NewFactTableInput(repo, "aaa", FactTable{RollbackFields: []string{"epoch"}}, "llm_annotated")}
	got, _, _, err := req.resolveFactTable()
	if err != nil || got.RollbackFields[0] != "epoch" {
		t.Fatal("explicit table not used")
	}
	req.FactTable = nil
	got, source, ok, err := req.resolveFactTable()
	if err != nil || !ok || source != "shipped_fixture" || got.RollbackFields[0] != "version" {
		t.Fatal("explicit table leaked into fixture lookup")
	}
}
