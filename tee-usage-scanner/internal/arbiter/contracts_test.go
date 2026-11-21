package arbiter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

func arbiterContractFixture(t *testing.T, registered bool) (contracts.BindingContext, artifacts.CaseInvariantV2, artifacts.ContractReview) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte("struct state { int version; int length; };\nvoid load(struct state *p) {\n  p->length = 4;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: artifacts.ScannedScope{RepoURL: "fixture", Commit: "rev"}}
	c := artifacts.CaseInvariantV2{Origin: "deterministic", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "load"}}, Preconditions: []string{"the function is called with a state object"}, RequiredProperty: artifacts.ContractProperty{Kind: "direct_struct_field_assignment", Statement: "load initializes the version", Destination: "state.version", TargetFields: []string{"version"}}, SecurityEffect: "version is used by a guard"}
	if registered {
		c.VerificationQueries = []artifacts.ContractQuery{{Backend: "codeql", Operation: "cpp.contract.direct_struct_field_assignment", Parameters: map[string]string{"type": "state", "field": "version"}}}
	} else {
		c.RequiredProperty.Kind = "value_propagation"
	}
	c, _, err := contracts.Bind(c, b)
	if err != nil {
		t.Fatal(err)
	}
	r := artifacts.ContractReview{InvariantID: c.InvariantID, Position: "supported", Reason: "anchored source supports the concern", PreconditionsSatisfied: true, AttackChainComplete: true, Witness: c.Subjects}
	return b, c, r
}

func arbiterAssessment(t *testing.T, b contracts.BindingContext, c artifacts.CaseInvariantV2, state string) artifacts.InvariantAssessment {
	t.Helper()
	a := artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: c.InvariantID, DefinitionHash: c.DefinitionHash, Scope: c.Scope,
		Assessment: state, ReasonCode: "query_" + state, Reason: "registered result", VerificationBasis: "registered_query", QueryOperation: "cpp.contract.direct_struct_field_assignment", SourceCorroborated: true, PreconditionsSatisfied: true, AttackChainComplete: true, EvidenceRefs: c.EvidenceRefs, Witness: c.Subjects}
	result, _ := json.Marshal(map[string]string{"assessment": state, "contract_hash": c.DefinitionHash, "reason_code": a.ReasonCode})
	f := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "q-" + c.InvariantID, Tool: "codeql", Operation: a.QueryOperation, RepoCommit: c.Scope.Commit, Status: "success", Result: result}
	ref, err := trustirfacts.Persist(b.RunDir, f)
	if err != nil {
		t.Fatal(err)
	}
	a.EvidenceRefs = append(append([]artifacts.ContractEvidenceRef{}, c.EvidenceRefs...), artifacts.ContractEvidenceRef{Kind: "tool_fact", Ref: ref})
	return a
}

func arbitrateFixture(b contracts.BindingContext, cs []artifacts.CaseInvariantV2, rs []artifacts.ContractReview, as []artifacts.InvariantAssessment) []artifacts.FindingItem {
	items, _ := arbitrateContracts(b.RunDir, artifacts.Manifest{LocalPath: b.RepoRoot, Scope: b.Scope}, artifacts.CasePack{CaseID: "case", Category: "state_machine", ContractRequired: true, CaseInvariants: cs},
		artifacts.Hypothesis{NeedsVerification: true, ContractReviews: rs}, artifacts.Challenge{ContractReviews: rs}, artifacts.VerificationMemo{Status: "contested", Contradictions: []string{"unrelated case-level statement"}, InvariantAssessments: as})
	return items
}

func TestArbiter_ConfirmedRequiresViolatedAssessment(t *testing.T) {
	b, c, r := arbiterContractFixture(t, true)
	a := arbiterAssessment(t, b, c, "violated")
	items := arbitrateFixture(b, []artifacts.CaseInvariantV2{c}, []artifacts.ContractReview{r}, []artifacts.InvariantAssessment{a})
	if items[0].Status != "confirmed_candidate" {
		t.Fatalf("valid violation: %+v", items[0])
	}
	a.AttackChainComplete = false
	items = arbitrateFixture(b, []artifacts.CaseInvariantV2{c}, []artifacts.ContractReview{r}, []artifacts.InvariantAssessment{a})
	if items[0].Status != "likely_issue" {
		t.Fatalf("incomplete chain: %+v", items[0])
	}
	a.Assessment = "unresolved"
	a.ReasonCode = "tool_error"
	a.VerificationBasis = "unresolved"
	items = arbitrateFixture(b, []artifacts.CaseInvariantV2{c}, []artifacts.ContractReview{r}, []artifacts.InvariantAssessment{a})
	if items[0].Status != "needs_review" {
		t.Fatalf("tool error promoted: %+v", items[0])
	}
}

func TestArbiter_LikelyIssueAllowedOnlyForUnregisteredQueryWithWitness(t *testing.T) {
	b, c, r := arbiterContractFixture(t, false)
	a := artifacts.InvariantAssessment{SchemaVersion: artifacts.SchemaVersionInvariantAssessmentV1, InvariantID: c.InvariantID, DefinitionHash: c.DefinitionHash, Scope: c.Scope, Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "query unavailable", VerificationBasis: "source_corroborated_no_query", SourceCorroborated: true, PreconditionsSatisfied: true, Witness: c.Subjects, EvidenceRefs: c.EvidenceRefs}
	for _, tc := range []struct {
		name, reason, want string
		witness            bool
	}{{"missing query", "no_registered_query", "likely_issue", true}, {"tool failure", "tool_error", "needs_review", true}, {"no witness", "no_registered_query", "needs_review", false}} {
		t.Run(tc.name, func(t *testing.T) {
			copy := a
			copy.ReasonCode = tc.reason
			if !tc.witness {
				copy.Witness = nil
			}
			items := arbitrateFixture(b, []artifacts.CaseInvariantV2{c}, []artifacts.ContractReview{r}, []artifacts.InvariantAssessment{copy})
			if items[0].Status != tc.want {
				t.Fatalf("got %+v", items[0])
			}
		})
	}
}

func TestArbiter_TwoInvariantsInSameCaseDoNotCrossContaminate(t *testing.T) {
	b, a, ra := arbiterContractFixture(t, true)
	bdef := contracts.LogicalDefinition(a)
	bdef.Origin = "deterministic"
	bdef.InvariantID = "contract-b"
	bdef.DefinitionHash = ""
	bdef.RequiredProperty.Destination = "state.length"
	bdef.RequiredProperty.TargetFields = []string{"length"}
	bdef.VerificationQueries[0].Parameters["field"] = "length"
	other, _, err := contracts.Bind(bdef, b)
	if err != nil {
		t.Fatal(err)
	}
	rb := ra
	rb.InvariantID = other.InvariantID
	rb.Position = "contradicted"
	rb.CounterEvidence = []string{"the length is assigned"}
	aa := arbiterAssessment(t, b, a, "violated")
	ab := arbiterAssessment(t, b, other, "satisfied")
	ab.Contradictions = []string{"violation disproved"}
	ab.MissingEvidence = []string{"resolve the reported conflict"}
	ab.AttackChainComplete = false
	items := arbitrateFixture(b, []artifacts.CaseInvariantV2{a, other}, []artifacts.ContractReview{ra, rb}, []artifacts.InvariantAssessment{aa, ab})
	if len(items) != 2 || items[0].Status != "confirmed_candidate" || items[1].Status != "needs_review" {
		t.Fatalf("cross-contract contamination: %+v", items)
	}
}
