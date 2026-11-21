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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
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
	if a.Assessment != "violated" || a.ReasonCode != "query_violated" || len(a.Contradictions) == 0 || len(a.MissingEvidence) == 0 || a.AttackChainComplete {
		t.Fatalf("expert counterevidence lost: %+v", a)
	}
}

func TestAssessContract_RegisteredResultSurvivesUnprovenPreconditions(t *testing.T) {
	for _, status := range []string{"satisfied", "violated"} {
		t.Run(status, func(t *testing.T) {
			b, c, r := contractFixture(t)
			r.PreconditionsSatisfied = false
			r.Position = "unresolved"
			r.Reason = "consumer definition is outside the source window"
			r.Witness = nil
			a := AssessContract(c, b, nil, nil, r, outcome(t, b, c, status))
			if a.Assessment != status || a.PreconditionsSatisfied || a.AttackChainComplete || len(a.MissingEvidence) == 0 || len(a.Witness) == 0 {
				t.Fatalf("registered result lost: %+v", a)
			}
			if err := contracts.ValidateAssessment(a, c, b); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAssessContract_SatisfiedKeepsMaterialCounterEvidence(t *testing.T) {
	b, c, r := contractFixture(t)
	r.Position = "supported"
	r.CounterEvidence = []string{"assignment is only in a test build"}
	a := AssessContract(c, b, nil, nil, r, outcome(t, b, c, "satisfied"))
	if a.Assessment != "satisfied" || len(a.Contradictions) == 0 || len(a.MissingEvidence) == 0 || a.AttackChainComplete {
		t.Fatalf("counter evidence dropped: %+v", a)
	}
	if err := contracts.ValidateAssessment(a, c, b); err != nil {
		t.Fatal(err)
	}
}

func TestAssessContract_SatisfiedKeepsEvidenceForTheFix(t *testing.T) {
	b, c, r := contractFixture(t)
	r.Position = "contradicted"
	r.CounterEvidence = []string{"the required assignment is present"}
	a := AssessContract(c, b, nil, nil, r, outcome(t, b, c, "satisfied"))
	if a.Assessment != "satisfied" || len(a.Contradictions) > 0 || !strings.Contains(a.Reason, r.CounterEvidence[0]) {
		t.Fatalf("repair evidence misclassified: %+v", a)
	}
}

type savedContractQuery struct{ result ContractQueryResult }

func (s savedContractQuery) Run(context.Context, artifacts.CaseInvariantV2, artifacts.ContractQuery) (ContractQueryResult, error) {
	return s.result, nil
}

func TestReverify_PreservesRegisteredResultWithoutModelContext(t *testing.T) {
	for _, status := range []string{"satisfied", "violated"} {
		t.Run(status, func(t *testing.T) {
			b, c, _ := contractFixture(t)
			a, err := ReverifyWithClient(context.Background(), config.Config{}, nil, c, b, savedContractQuery{outcome(t, b, c, status)})
			if err != nil {
				t.Fatal(err)
			}
			if a.Assessment != status || a.PreconditionsSatisfied || a.AttackChainComplete || len(a.MissingEvidence) == 0 {
				t.Fatalf("context-free query verdict: %+v", a)
			}
		})
	}
}

func TestAssessContract_NoQuerySourceContradictedIsExplicit(t *testing.T) {
	b, c, r := contractFixture(t)
	c.RequiredProperty.Kind = "value_propagation"
	c.VerificationQueries = nil
	c.DefinitionHash = contracts.DefinitionHash(c)
	r.Position = "contradicted"
	r.PreconditionsSatisfied = false
	r.Reason = "the current source includes the required validation"
	a := AssessContract(c, b, nil, nil, r, ContractQueryResult{Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "not implemented"})
	if a.Assessment != "unresolved" || a.ReasonCode != "source_contradicted" {
		t.Fatalf("source correction not distinguished: %+v", a)
	}
	failed := AssessContract(c, b, nil, nil, r, ContractQueryResult{Assessment: "unresolved", ReasonCode: "tool_error", Reason: "database failure"})
	if failed.ReasonCode != "tool_error" {
		t.Fatalf("source review hid tool error: %+v", failed)
	}
}

func TestRegisteredContractQuery_ExplicitTargetSurvivesSubjectReordering(t *testing.T) {
	b, c, _ := contractFixture(t)
	if err := os.WriteFile(filepath.Join(b.RepoRoot, "consumer.c"), []byte("int check_version(int v) { return v > 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	consumer, err := contracts.BindSubject(artifacts.ContractSubject{Path: "consumer.c", Symbol: "check_version"}, b)
	if err != nil {
		t.Fatal(err)
	}
	c.Subjects = append(c.Subjects, consumer)
	q := c.VerificationQueries[0]
	if _, err := fieldWriteQuery(c, q); err == nil {
		t.Fatal("ambiguous query target accepted")
	}
	q.Parameters["subject"] = "state.c::load"
	c.DefinitionHash = contracts.DefinitionHash(c)
	before, err := fieldWriteQuery(c, q)
	if err != nil {
		t.Fatal(err)
	}
	c.Subjects[0], c.Subjects[1] = c.Subjects[1], c.Subjects[0]
	if c.DefinitionHash != contracts.DefinitionHash(c) {
		t.Fatal("context subject order changed definition")
	}
	after, err := fieldWriteQuery(c, q)
	if err != nil || before != after {
		t.Fatalf("query target changed after reorder: %v", err)
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
