package trustirfacts

import (
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// realRegistry loads the actual enum_registry.yml — the single vocabulary
// §23.4.2 requires the resolver to check against, not a re-declared test
// copy.
func realRegistry(t *testing.T) twe.EnumRegistry {
	t.Helper()
	path := filepath.Join("..", "..", "knowledge", "twe", "definitions", "enum_registry.yml")
	reg, err := twe.LoadEnumRegistry(path)
	if err != nil {
		t.Fatalf("load enum registry: %v", err)
	}
	return reg
}

func rollbackCandidates() Candidates {
	return Candidates{
		Functions: []FunctionCandidate{
			{Name: "shdr_load_pub_key", Files: []string{"a.c"}},
			{Name: "check_update_version", Files: []string{"b.c"}},
		},
		Fields:  []string{"version", "max_depth"},
		Structs: []string{"shdr_pub_key"},
	}
}

func TestResolveAnnotations_AcceptsWellFormedResponse(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	resp.ClaimProducers = append(resp.ClaimProducers, struct {
		Function string `json:"function"`
		Role     string `json:"role"`
	}{Function: "shdr_load_pub_key", Role: "security_version"})
	resp.RollbackAuthorities = append(resp.RollbackAuthorities, struct {
		Function string `json:"function"`
		Kind     string `json:"kind"`
	}{Function: "check_update_version", Kind: "state_restore_acceptance"})
	resp.RollbackFields = []string{"version"}
	resp.ProducedStructs = []string{"shdr_pub_key"}

	table, unresolved := resolveAnnotations(resp, cand, registry)
	if len(unresolved) != 0 {
		t.Fatalf("expected no unresolved annotations, got %+v", unresolved)
	}
	if len(table.ClaimProducers) != 1 || table.ClaimProducers[0].Function != "shdr_load_pub_key" || table.ClaimProducers[0].Role != "security_version" {
		t.Errorf("ClaimProducers = %+v", table.ClaimProducers)
	}
	if len(table.RollbackAuthorities) != 1 || table.RollbackAuthorities[0].Function != "check_update_version" {
		t.Errorf("RollbackAuthorities = %+v", table.RollbackAuthorities)
	}
	if len(table.RollbackFields) != 1 || table.RollbackFields[0] != "version" {
		t.Errorf("RollbackFields = %+v", table.RollbackFields)
	}
	if len(table.ProducedStructs) != 1 || table.ProducedStructs[0] != "shdr_pub_key" {
		t.Errorf("ProducedStructs = %+v", table.ProducedStructs)
	}
}

func TestResolveAnnotations_RejectsUnknownFunctionName(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	resp.ClaimProducers = append(resp.ClaimProducers, struct {
		Function string `json:"function"`
		Role     string `json:"role"`
	}{Function: "totally_invented_function", Role: "security_version"})

	table, unresolved := resolveAnnotations(resp, cand, registry)
	if len(table.ClaimProducers) != 0 {
		t.Errorf("an unresolvable function name must not enter the fact table, got %+v", table.ClaimProducers)
	}
	if len(unresolved) != 1 {
		t.Fatalf("expected exactly one unresolved annotation, got %+v", unresolved)
	}
	if unresolved[0].Category != "claim_producer" || unresolved[0].Value != "totally_invented_function" {
		t.Errorf("unresolved[0] = %+v", unresolved[0])
	}
}

// TestResolveAnnotations_RejectsRoleNotInRegistry is the §23.4.2 fatal-bug
// regression test: a role/kind value the model invents (not a member of
// enum_registry.yml) must never reach the rendered fact table, even when
// the function name itself is perfectly real.
func TestResolveAnnotations_RejectsRoleNotInRegistry(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	resp.ClaimProducers = append(resp.ClaimProducers, struct {
		Function string `json:"function"`
		Role     string `json:"role"`
	}{Function: "shdr_load_pub_key", Role: "not_a_real_registry_value"})

	table, unresolved := resolveAnnotations(resp, cand, registry)
	if len(table.ClaimProducers) != 0 {
		t.Errorf("a role outside enum_registry.yml must never reach the fact table, got %+v", table.ClaimProducers)
	}
	if len(unresolved) != 1 || unresolved[0].Reason == "" {
		t.Fatalf("expected one unresolved annotation with a reason, got %+v", unresolved)
	}
}

func TestResolveAnnotations_RejectsUnknownKind(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	resp.RollbackAuthorities = append(resp.RollbackAuthorities, struct {
		Function string `json:"function"`
		Kind     string `json:"kind"`
	}{Function: "check_update_version", Kind: "made_up_kind"})

	table, unresolved := resolveAnnotations(resp, cand, registry)
	if len(table.RollbackAuthorities) != 0 {
		t.Errorf("a kind outside enum_registry.yml must never reach the fact table, got %+v", table.RollbackAuthorities)
	}
	if len(unresolved) != 1 || unresolved[0].Category != "rollback_authority" {
		t.Fatalf("expected one unresolved rollback_authority, got %+v", unresolved)
	}
}

func TestResolveAnnotations_RejectsUnknownFieldAndStruct(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	resp.RollbackFields = []string{"not_a_real_field"}
	resp.ProducedStructs = []string{"not_a_real_struct"}

	table, unresolved := resolveAnnotations(resp, cand, registry)
	if len(table.RollbackFields) != 0 || len(table.ProducedStructs) != 0 {
		t.Errorf("unresolvable field/struct names must not reach the fact table: %+v / %+v", table.RollbackFields, table.ProducedStructs)
	}
	if len(unresolved) != 2 {
		t.Fatalf("expected two unresolved annotations, got %+v", unresolved)
	}
}

func TestResolveAnnotations_DeduplicatesRepeatedEntries(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	for i := 0; i < 3; i++ {
		resp.ClaimProducers = append(resp.ClaimProducers, struct {
			Function string `json:"function"`
			Role     string `json:"role"`
		}{Function: "shdr_load_pub_key", Role: "security_version"})
	}
	resp.RollbackFields = []string{"version", "version", "version"}

	table, unresolved := resolveAnnotations(resp, cand, registry)
	if len(unresolved) != 0 {
		t.Fatalf("duplicates are not rejections, got unresolved=%+v", unresolved)
	}
	if len(table.ClaimProducers) != 1 {
		t.Errorf("expected exactly one deduplicated ClaimProducer, got %+v", table.ClaimProducers)
	}
	if len(table.RollbackFields) != 1 {
		t.Errorf("expected exactly one deduplicated RollbackField, got %+v", table.RollbackFields)
	}
}

func TestResolveAnnotations_EmptyResponseYieldsEmptyTable(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	table, unresolved := resolveAnnotations(annotationResponse{}, cand, registry)
	if !table.Empty() {
		t.Errorf("expected an Empty table for an empty response, got %+v", table)
	}
	if len(unresolved) != 0 {
		t.Errorf("expected no unresolved entries for an empty response, got %+v", unresolved)
	}
}

// TestResolveAnnotations_TableRendersLikeTheDeterministicFixture proves the
// resolved output is not just structurally similar but byte-identical in
// shape to the hand-authored knownFactTables fixture (facttable.go) for the
// same case — the resolver's job is to reproduce the deterministic fixture
// FROM real annotations, not to invent a parallel format.
func TestResolveAnnotations_TableRendersLikeTheDeterministicFixture(t *testing.T) {
	registry := realRegistry(t)
	cand := rollbackCandidates()

	var resp annotationResponse
	resp.ClaimProducers = append(resp.ClaimProducers, struct {
		Function string `json:"function"`
		Role     string `json:"role"`
	}{Function: "shdr_load_pub_key", Role: "security_version"})
	resp.RollbackAuthorities = append(resp.RollbackAuthorities, struct {
		Function string `json:"function"`
		Kind     string `json:"kind"`
	}{Function: "check_update_version", Kind: "state_restore_acceptance"})
	resp.RollbackFields = []string{"version"}
	resp.ProducedStructs = []string{"shdr_pub_key"}

	table, _ := resolveAnnotations(resp, cand, registry)
	got := table.Render()
	fixture := knownFactTables["github.com/op-tee/optee_os"].Render()
	if got != fixture {
		t.Errorf("LLM-resolved table renders differently from the hand-authored fixture for the same facts:\n--- resolved ---\n%s\n--- fixture ---\n%s", got, fixture)
	}
}
