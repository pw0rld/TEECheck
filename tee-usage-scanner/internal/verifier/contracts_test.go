package verifier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

func contractFixture(t *testing.T) (contracts.BindingContext, artifacts.CaseInvariantV2, artifacts.ContractReview) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "state.c"), []byte("struct key { int version; };\nvoid load(struct key *key) {\n  key->version = 1;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: artifacts.ScannedScope{RepoURL: "fixture", Commit: "rev", Root: root}}
	c, _, err := contracts.Bind(artifacts.CaseInvariantV2{Origin: "deterministic", Subjects: []artifacts.ContractSubject{{Path: "state.c", Symbol: "load"}},
		Preconditions: []string{"function and field exist"}, RequiredProperty: artifacts.ContractProperty{Kind: "direct_struct_field_assignment", Statement: "load writes key.version", Destination: "key.version", TargetFields: []string{"version"}},
		SecurityEffect: "version is consumed by an acceptance check", VerificationQueries: []artifacts.ContractQuery{{Backend: "codeql", Operation: StructFieldWriteOperation, Parameters: map[string]string{"type": "key", "field": "version"}}}}, b)
	if err != nil {
		t.Fatal(err)
	}
	r := artifacts.ContractReview{InvariantID: c.InvariantID, Position: "supported", Reason: "source supports the local claim", PreconditionsSatisfied: true, AttackChainComplete: true, Witness: c.Subjects}
	return b, c, r
}

func outcome(t *testing.T, b contracts.BindingContext, c artifacts.CaseInvariantV2, status string) ContractQueryResult {
	t.Helper()
	result, _ := json.Marshal(map[string]string{"assessment": status, "contract_hash": c.DefinitionHash, "reason_code": "query_" + status})
	f := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "query-" + status, Tool: "codeql", Operation: StructFieldWriteOperation, RepoCommit: c.Scope.Commit, Status: "success", Result: result}
	path, err := trustirfacts.Persist(b.RunDir, f)
	if err != nil {
		t.Fatal(err)
	}
	return ContractQueryResult{Assessment: status, ReasonCode: "query_" + status, Reason: "registered query result", Fact: f, FactRef: path}
}

func TestAssessContract_FixedSatisfactionIsNotAViolationOpinion(t *testing.T) {
	b, c, r := contractFixture(t)
	r.Position = "contradicted"
	a := AssessContract(c, b, nil, nil, r, outcome(t, b, c, "satisfied"))
	if a.Assessment != "satisfied" || !a.SourceCorroborated {
		t.Fatalf("assessment: %+v", a)
	}
	if err := contracts.ValidateAssessment(a, c, b); err != nil {
		t.Fatal(err)
	}
}

func TestAssessContract_QueryFailureCannotUseSourceException(t *testing.T) {
	b, c, r := contractFixture(t)
	a := AssessContract(c, b, []artifacts.ContractReview{r}, []artifacts.ContractReview{r}, r, ContractQueryResult{Assessment: "unresolved", ReasonCode: "tool_error", Reason: "failed"})
	if a.Assessment != "unresolved" || a.VerificationBasis == "source_corroborated_no_query" {
		t.Fatalf("assessment: %+v", a)
	}
}

func TestAssessContract_ExpertCounterevidenceCannotDisappear(t *testing.T) {
	b, c, r := contractFixture(t)
	e := r
	e.Position, e.CounterEvidence = "contradicted", []string{"another source path establishes the property"}
	a := AssessContract(c, b, []artifacts.ContractReview{e}, []artifacts.ContractReview{r}, r, outcome(t, b, c, "violated"))
	if a.Assessment != "unresolved" || a.ReasonCode != "counterevidence" || len(a.Contradictions) == 0 {
		t.Fatalf("expert counterevidence lost: %+v", a)
	}
}

func TestAssessContract_OnlyMissingQueryAllowsSourceBasis(t *testing.T) {
	b, c, r := contractFixture(t)
	c.RequiredProperty.Kind = "value_propagation"
	c.VerificationQueries = nil
	c.DefinitionHash = contracts.DefinitionHash(c)
	a := AssessContract(c, b, []artifacts.ContractReview{r}, []artifacts.ContractReview{r}, r, ContractQueryResult{Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "not implemented"})
	if a.Assessment != "unresolved" || a.VerificationBasis != "source_corroborated_no_query" {
		t.Fatalf("assessment: %+v", a)
	}
	r.CounterEvidence = []string{"a separate guard may apply"}
	a = AssessContract(c, b, []artifacts.ContractReview{r}, []artifacts.ContractReview{r}, r, ContractQueryResult{Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "not implemented"})
	if a.VerificationBasis == "source_corroborated_no_query" {
		t.Fatalf("counterevidence ignored: %+v", a)
	}
}

type contractEngine struct {
	results []codeql.Result
	query   string
}

func (e *contractEngine) Available() bool { return true }
func (e *contractEngine) Analyze(_ context.Context, o codeql.AnalyzeOptions) ([]codeql.Result, error) {
	data, _ := os.ReadFile(o.Queries[0])
	e.query = string(data)
	return e.results, nil
}

type contractDB struct{}

func (contractDB) Ensure(context.Context, codedb.Scope) (string, error) { return "/fixture-db", nil }
func (contractDB) Path(codedb.Scope) string                             { return "/fixture-db" }
func (contractDB) State(codedb.Scope) string                            { return codedb.StateReady }

func TestRegisteredContractQuery_EmptyResultIsUnresolved(t *testing.T) {
	b, c, _ := contractFixture(t)
	e := &contractEngine{}
	runner := NewContractQueryRunner(e, contractDB{}, b.RunDir)
	r, err := runner.Run(context.Background(), c, c.VerificationQueries[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.Assessment != "unresolved" || r.ReasonCode != "query_unresolved" {
		t.Fatalf("empty query: %+v", r)
	}
	if !strings.Contains(e.query, `d.getFile().getRelativePath() = "state.c"`) || !strings.Contains(e.query, "a.getFile() = d.getFile()") || !strings.Contains(e.query, "select d,") {
		t.Fatal("query not bound to source file")
	}
}

func TestRegisteredContractQuery_ReportsBothSides(t *testing.T) {
	for _, tc := range []struct{ message, want string }{{"written", "satisfied"}, {"missing", "violated"}} {
		t.Run(tc.message, func(t *testing.T) {
			b, c, _ := contractFixture(t)
			e := &contractEngine{results: []codeql.Result{{Path: "state.c", StartLine: c.Subjects[0].StartLine, Message: "teecheck-contract-field:" + tc.message}}}
			r, err := NewContractQueryRunner(e, contractDB{}, b.RunDir).Run(context.Background(), c, c.VerificationQueries[0])
			if err != nil {
				t.Fatal(err)
			}
			if r.Assessment != tc.want {
				t.Fatalf("result %+v", r)
			}
		})
	}
}

func TestRegisteredContractQuery_RejectsParameterPropertyMismatch(t *testing.T) {
	_, c, _ := contractFixture(t)
	q := c.VerificationQueries[0]
	q.Parameters["field"] = "other"
	if _, err := fieldWriteQuery(c, q); err == nil {
		t.Fatal("different property accepted")
	}
}

func TestRegisteredContractQuery_DifferentOutcomesKeepImmutableEvidence(t *testing.T) {
	b, c, _ := contractFixture(t)
	e := &contractEngine{}
	runner := NewContractQueryRunner(e, contractDB{}, b.RunDir)
	first, err := runner.Run(context.Background(), c, c.VerificationQueries[0])
	if err != nil {
		t.Fatal(err)
	}
	e.results = []codeql.Result{{Path: "state.c", StartLine: c.Subjects[0].StartLine, Message: "teecheck-contract-field:written"}}
	second, err := runner.Run(context.Background(), c, c.VerificationQueries[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.FactRef == second.FactRef || first.Fact.ArgumentsSHA256 != second.Fact.ArgumentsSHA256 || second.Assessment != "satisfied" {
		t.Fatalf("execution identities collapsed: %+v %+v", first, second)
	}
}

func TestRegisteredContractQuery_RejectsStrongerAuthorityConstraint(t *testing.T) {
	_, c, _ := contractFixture(t)
	c.RequiredProperty.Authority = "check_version"
	if _, err := fieldWriteQuery(c, c.VerificationQueries[0]); err == nil {
		t.Fatal("ignored authority constraint")
	}
}
