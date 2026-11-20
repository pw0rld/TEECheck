package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func draft() artifacts.CaseInvariantV2 {
	return artifacts.CaseInvariantV2{InvariantID: "inv-1", Origin: "planner", LeadRef: "lead-1", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, Preconditions: []string{"the signed header is accepted"}, RequiredProperty: artifacts.ContractProperty{Kind: "field_propagation", Statement: "header version must reach key version", Source: "header.version", Destination: "key.version", TargetFields: []string{"key.version"}}, SecurityEffect: "version governs acceptance"}
}
func fixture(t *testing.T, body, commit string) BindingContext {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return BindingContext{RepoRoot: root, Scope: artifacts.ScannedScope{RepoURL: "fixture", Commit: commit}}
}
func TestBindContract_HandlesLineShiftAcrossPatch(t *testing.T) {
	a := fixture(t, "int load(void) { return 1; }\n", "old")
	bound, diags, err := Bind(draft(), a)
	if err != nil || len(diags) != 0 || bound.Grounding != "source_bound" {
		t.Fatalf("bind: %+v %+v %v", bound, diags, err)
	}
	b := fixture(t, "// shifted\n\nint load(void) { return 2; }\n", "new")
	logical := LogicalDefinition(bound)
	if len(logical.EvidenceRefs) != 0 || logical.Subjects[0].StartLine != 0 || logical.Subjects[0].ContentSHA256 != "" || logical.Scope.Commit != "" {
		t.Fatalf("old evidence leaked: %+v", logical)
	}
	rebound, diags, err := Bind(logical, b)
	if err != nil || len(diags) != 0 || rebound.Subjects[0].StartLine != 3 {
		t.Fatalf("rebind: %+v %+v %v", rebound, diags, err)
	}
	if bound.DefinitionHash != rebound.DefinitionHash {
		t.Fatal("logical definition changed on line shift")
	}
	if bound.Subjects[0].ContentSHA256 == rebound.Subjects[0].ContentSHA256 {
		t.Fatal("source modification not reflected")
	}
}
func TestBindContract_AmbiguousStaticSymbolReturnsUnresolved(t *testing.T) {
	ctx := fixture(t, "static int load(void) { return 1; }\nstatic int load(void) { return 2; }\n", "rev")
	c, diags, err := Bind(draft(), ctx)
	if err != nil || c.Grounding != "unresolved" || len(diags) == 0 {
		t.Fatalf("ambiguous binding: %+v %+v %v", c, diags, err)
	}
}
func TestBindContract_RejectsProvidedStaleAnchor(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\n", "rev")
	c := draft()
	c.Subjects[0].ContentSHA256 = strings.Repeat("0", 64)
	if _, _, err := Bind(c, ctx); err == nil {
		t.Fatal("stale supplied hash overwritten")
	}
}
func TestContract_WithoutRegisteredQueryIsValid(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\n", "rev")
	c, _, err := Bind(draft(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate(c, ctx); err != nil {
		t.Fatal(err)
	}
}
func TestContractPropertyKeySeparatesProperties(t *testing.T) {
	a := draft()
	b := draft()
	b.RequiredProperty.Kind = "guard_dominance"
	if PropertyKey(a) == PropertyKey(b) {
		t.Fatal("two properties on same function collapsed")
	}
	b = draft()
	b.RequiredProperty.TargetFields = []string{"key.modulus"}
	if PropertyKey(a) == PropertyKey(b) {
		t.Fatal("different property targets collapsed")
	}
}

func TestBindContract_MultilineDefinitionAndCommentLookalike(t *testing.T) {
	ctx := fixture(t, "// int load(void) { invented(); }\nstatic int\nload(void)\n{\n return 1;\n}\n", "rev")
	c, ds, err := Bind(draft(), ctx)
	if err != nil || len(ds) > 0 || c.Subjects[0].StartLine != 2 || c.Subjects[0].EndLine != 6 {
		t.Fatalf("multiline definition: %+v %+v %v", c, ds, err)
	}
}
func TestContract_ExistingHashAndLineCannotBeRepairedByBinding(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\n", "rev")
	c, _, err := Bind(draft(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.Subjects[0].StartLine = 99
	if _, _, err := Bind(c, ctx); err == nil {
		t.Fatal("invalid supplied line silently overwritten")
	}
}
func TestReverify_StripsVulnerableWitnessBeforeFixedBinding(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\n", "old")
	c, _, err := Bind(draft(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.EvidenceRefs = append(c.EvidenceRefs, artifacts.ContractEvidenceRef{Kind: "observation", Ref: "obs:old"})
	logical := LogicalDefinition(c)
	if len(logical.EvidenceRefs) != 0 || logical.LeadRef != "" || logical.Scope != (artifacts.ScannedScope{}) || logical.Subjects[0].SymbolID != "" {
		t.Fatalf("vulnerable context survived: %+v", logical)
	}
}
func TestValidateAssessment_RejectsCrossContractAndWitness(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\nint other(void) { return 2; }\n", "rev")
	c, _, err := Bind(draft(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: c.InvariantID, DefinitionHash: c.DefinitionHash, Scope: c.Scope, Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "no query registered", VerificationBasis: "source_corroborated_no_query", SourceCorroborated: true, PreconditionsSatisfied: true, Witness: c.Subjects, EvidenceRefs: c.EvidenceRefs}
	if err := ValidateAssessment(a, c, ctx); err != nil {
		t.Fatal(err)
	}
	wrong, err := BindSubject(artifacts.ContractSubject{Path: "a.c", Symbol: "other"}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	a.Witness = []artifacts.ContractSubject{wrong}
	if err := ValidateAssessment(a, c, ctx); err == nil {
		t.Fatal("other-contract witness accepted")
	}
	a.Witness = c.Subjects
	a.DefinitionHash = strings.Repeat("0", 64)
	if err := ValidateAssessment(a, c, ctx); err == nil {
		t.Fatal("wrong definition accepted")
	}
}

func TestAssessment_RequiresMatchingQueryResultWithoutRequiringFullAttackChain(t *testing.T) {
	ctx := fixture(t, "int load(void) { return 1; }\n", "rev")
	ctx.RunDir = t.TempDir()
	c := draft()
	c.VerificationQueries = []artifacts.ContractQuery{{Backend: "codeql", Operation: "cpp.contract.struct_field_write", Parameters: map[string]string{"type": "key", "field": "version"}}}
	bound, _, err := Bind(c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"satisfied", "violated"} {
		t.Run(status, func(t *testing.T) {
			fact := artifacts.ToolFact{SchemaVersion: "teecheck.trustir_result.v1", RequestID: "q", FactID: "f", Tool: "codeql", Operation: c.VerificationQueries[0].Operation, RepoCommit: "rev", Status: "success"}
			result, _ := json.Marshal(map[string]string{"assessment": status, "contract_hash": bound.DefinitionHash, "reason_code": "query_checked"})
			fact.Result = result
			path := filepath.Join(ctx.RunDir, "fact.json")
			write := func() {
				data, _ := json.Marshal(fact)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write()
			assessment := artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: bound.InvariantID, DefinitionHash: bound.DefinitionHash, Scope: bound.Scope, Assessment: status, ReasonCode: "query_checked", Reason: "registered local property query", VerificationBasis: "registered_query", QueryOperation: fact.Operation, SourceCorroborated: true, PreconditionsSatisfied: true, AttackChainComplete: false, Witness: bound.Subjects, EvidenceRefs: append(append([]artifacts.ContractEvidenceRef{}, bound.EvidenceRefs...), artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: path})}
			if err := ValidateAssessment(assessment, bound, ctx); err != nil {
				t.Fatal(err)
			}
			fact.Result = json.RawMessage(`{}`)
			write()
			if err := ValidateAssessment(assessment, bound, ctx); err == nil {
				t.Fatal("success-only fact forged a proved assessment")
			}
			fact.Result = json.RawMessage(`{"assessment":"violated","contract_hash":"other","reason_code":"query_checked"}`)
			write()
			if err := ValidateAssessment(assessment, bound, ctx); err == nil {
				t.Fatal("another contract result accepted")
			}
		})
	}
}
