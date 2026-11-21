package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

const StructFieldWriteOperation = "cpp.contract.direct_struct_field_assignment"

// ContractQueryResult is produced by a registered executor, never by a model.
// Missing query matches remain unresolved instead of being interpreted as safe.
type ContractQueryResult struct {
	Assessment string
	ReasonCode string
	Reason     string
	Fact       artifacts.ToolFact
	FactRef    string
}

type ContractQueryRunner interface {
	Run(context.Context, artifacts.CaseInvariantV2, artifacts.ContractQuery) (ContractQueryResult, error)
}

type ContractQueryEngine interface {
	Available() bool
	Analyze(context.Context, codeql.AnalyzeOptions) ([]codeql.Result, error)
}

type registeredContractRunner struct {
	engine ContractQueryEngine
	db     codedb.DatabaseProvider
	runDir string
}

func NewContractQueryRunner(engine ContractQueryEngine, db codedb.DatabaseProvider, runDir string) ContractQueryRunner {
	return &registeredContractRunner{engine: engine, db: db, runDir: runDir}
}

// Only this narrow, explicitly stated property is registered initially. It
// proves the presence of a struct-field assignment in a function, not value
// provenance, dominance, output-pointer aliasing, or all-path propagation.
func registeredQuery(c artifacts.CaseInvariantV2, q artifacts.ContractQuery) bool {
	return q.Backend == "codeql" && q.Operation == StructFieldWriteOperation && c.RequiredProperty.Kind == "direct_struct_field_assignment"
}

var contractIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func fieldWriteQuery(c artifacts.CaseInvariantV2, q artifacts.ContractQuery) (string, error) {
	if !registeredQuery(c, q) || len(c.Subjects) == 0 || len(q.Parameters) < 2 || len(q.Parameters) > 3 {
		return "", fmt.Errorf("query does not describe one registered struct-field property")
	}
	for name := range q.Parameters {
		if name != "type" && name != "field" && name != "subject" {
			return "", fmt.Errorf("unknown query parameter %q", name)
		}
	}
	s, err := fieldWriteSubject(c, q)
	if err != nil {
		return "", err
	}
	typeName, field := q.Parameters["type"], q.Parameters["field"]
	if !contractIdentifier.MatchString(typeName) || !contractIdentifier.MatchString(field) || !contractIdentifier.MatchString(s.Symbol) {
		return "", fmt.Errorf("invalid query identifier")
	}
	if c.RequiredProperty.Destination != typeName+"."+field || len(c.RequiredProperty.TargetFields) != 1 || c.RequiredProperty.TargetFields[0] != field || c.RequiredProperty.Source != "" || c.RequiredProperty.Authority != "" {
		return "", fmt.Errorf("query parameters differ from the declared property")
	}
	return fmt.Sprintf(`/**
 * @name Contract struct field assignment
 * @description Reports a positive or negative answer for one exact function and declared struct field.
 * @kind problem
 * @id cpp/teecheck-contract-direct-struct-field-assignment
 * @problem.severity recommendation
 */
import cpp
predicate writesField(FunctionDeclarationEntry d) {
  exists(Assignment a, FieldAccess fa |
    a.getLValue() = fa and fa.getEnclosingFunction() = d.getFunction() and
    a.getFile() = d.getFile() and
    a.getLocation().getStartLine() >= d.getLocation().getStartLine() and
    a.getLocation().getEndLine() <= d.getLocation().getEndLine() and
    fa.getTarget().getName() = %s and
    fa.getTarget().getDeclaringType().getName() = %s
  )
}
from FunctionDeclarationEntry d, string answer
where
  d = d.getFunction().getDefinition() and
  d.getFunction().getName() = %s and d.getFile().getRelativePath() = %s and
  d.getLocation().getStartLine() >= %d and d.getLocation().getStartLine() <= %d and
  count(Field field | field.getName() = %s and field.getDeclaringType().getName() = %s) = 1 and
  ((writesField(d) and answer = "written") or (not writesField(d) and answer = "missing"))
select d, "teecheck-contract-field:" + answer
`, strconv.Quote(field), strconv.Quote(typeName), strconv.Quote(s.Symbol), strconv.Quote(filepath.ToSlash(s.Path)), s.StartLine, s.EndLine, strconv.Quote(field), strconv.Quote(typeName)), nil
}

// Explicitly bind the query target when context contains more than one
// function. Subject ordering is not part of a logical contract's identity.
func fieldWriteSubject(c artifacts.CaseInvariantV2, q artifacts.ContractQuery) (artifacts.ContractSubject, error) {
	target := q.Parameters["subject"]
	if target == "" && len(c.Subjects) == 1 {
		return c.Subjects[0], nil
	}
	var found []artifacts.ContractSubject
	for _, s := range c.Subjects {
		if target == s.Path+"::"+s.Symbol {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		return artifacts.ContractSubject{}, fmt.Errorf("query requires a unique subject parameter for its target definition")
	}
	return found[0], nil
}

func (r *registeredContractRunner) Run(ctx context.Context, c artifacts.CaseInvariantV2, q artifacts.ContractQuery) (ContractQueryResult, error) {
	result := ContractQueryResult{Assessment: "unresolved", ReasonCode: "no_registered_query", Reason: "No registered executor for this property and operation."}
	if !registeredQuery(c, q) {
		return result, nil
	}
	if c.Scope.Root == "" || c.Grounding != "source_bound" {
		result.ReasonCode, result.Reason = "source_scope_unverified", "Registered queries require a bound source root."
		return result, nil
	}
	if err := contracts.Validate(c, contracts.BindingContext{RunDir: r.runDir, RepoRoot: c.Scope.Root, Scope: c.Scope}); err != nil {
		result.ReasonCode, result.Reason = "source_scope_unverified", err.Error()
		return result, nil
	}
	query, err := fieldWriteQuery(c, q)
	if err != nil {
		result.ReasonCode, result.Reason = "query_property_mismatch", err.Error()
		return result, nil
	}
	subject, _ := fieldWriteSubject(c, q)
	if r.engine == nil || !r.engine.Available() || r.db == nil {
		result.ReasonCode, result.Reason = "tool_unavailable", "Registered CodeQL executor is unavailable."
		return result, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	dbPath, err := r.db.Ensure(ctx, codedb.Scope{RunDir: r.runDir, Repository: c.Scope.RepoURL, Commit: c.Scope.Commit})
	if err != nil {
		result.ReasonCode, result.Reason = "tool_error", err.Error()
		return result, nil
	}
	// A recheck may read a local fixture while the manager extracts a pinned
	// checkout. Verify their subject files are identical before joining the
	// tool result to local source witnesses.
	if sourceDB, ok := r.db.(interface{ SourceDir(codedb.Scope) string }); ok {
		dbRoot := sourceDB.SourceDir(codedb.Scope{RunDir: r.runDir, Repository: c.Scope.RepoURL, Commit: c.Scope.Commit})
		for _, anchor := range c.Subjects {
			local, localErr := os.ReadFile(filepath.Join(c.Scope.Root, anchor.Path))
			extracted, extractedErr := os.ReadFile(filepath.Join(dbRoot, anchor.Path))
			if localErr != nil || extractedErr != nil || sha256.Sum256(local) != sha256.Sum256(extracted) {
				result.ReasonCode, result.Reason = "source_scope_mismatch", "The database source does not match the bound subject file."
				return result, nil
			}
		}
	}
	version := "unknown"
	if m, err := runfs.LoadManifest(r.runDir); err == nil && m.ToolVersions["codeql"] != "" {
		version = m.ToolVersions["codeql"]
	}
	identity, _ := json.Marshal(struct {
		Contract       artifacts.CaseInvariantV2
		Query, Version string
	}{c, query, version})
	sum := sha256.Sum256(identity)
	key := hex.EncodeToString(sum[:])
	queryDir := filepath.Join(runfs.VerifierDir(r.runDir), "contract_queries", key)
	if err := os.MkdirAll(queryDir, 0o755); err != nil {
		return result, err
	}
	queryPath := filepath.Join(queryDir, "query.ql")
	if err := os.WriteFile(queryPath, []byte(query), 0o644); err != nil {
		return result, err
	}
	if err := os.WriteFile(filepath.Join(queryDir, "qlpack.yml"), []byte("name: teecheck/contract-query\nversion: 0.0.1\ndependencies:\n  codeql/cpp-all: \"*\"\n"), 0o644); err != nil {
		return result, err
	}
	rows, runErr := r.engine.Analyze(ctx, codeql.AnalyzeOptions{DBPath: dbPath, Queries: []string{queryPath}})
	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, FactID: "contract-query-" + key,
		Tool: "codeql", ToolVersion: version, Operation: q.Operation, RepoCommit: c.Scope.Commit, ArgumentsSHA256: key, Status: "success",
		CoverageGaps: []string{"Only a direct Assignment AST node in this source definition is checked. Initializers, helper calls, overloaded operators, and indirect writes do not satisfy this syntactic property. Value provenance, path dominance, output aliasing and build reachability are not proved."}}
	result.ReasonCode, result.Reason = "query_unresolved", "The query did not uniquely resolve the requested function and struct field."
	if runErr != nil {
		fact.Status, fact.Error = "error", runErr.Error()
		result.ReasonCode, result.Reason = "tool_error", runErr.Error()
	} else {
		for _, row := range rows {
			fact.Locations = append(fact.Locations, artifacts.ToolLocation{Path: row.Path, StartLine: row.StartLine, EndLine: row.EndLine, Symbol: subject.Symbol})
			fact.Findings = append(fact.Findings, artifacts.ToolFinding{Message: row.Message, Location: fact.Locations[len(fact.Locations)-1]})
		}
		if len(rows) == 1 && filepath.ToSlash(rows[0].Path) == filepath.ToSlash(subject.Path) && rows[0].StartLine >= subject.StartLine && rows[0].StartLine <= subject.EndLine {
			switch strings.TrimSpace(rows[0].Message) {
			case "teecheck-contract-field:written":
				result.Assessment, result.ReasonCode, result.Reason = "satisfied", "query_satisfied", "The requested definition contains a direct AST assignment to the declared struct field."
			case "teecheck-contract-field:missing":
				result.Assessment, result.ReasonCode, result.Reason = "violated", "query_violated", "The requested definition contains no direct AST assignment to the declared struct field; this does not exclude indirect writes."
			}
		}
	}
	payload, _ := json.Marshal(map[string]string{"assessment": result.Assessment, "reason_code": result.ReasonCode, "contract_hash": c.DefinitionHash})
	fact.Result = payload
	outcome, _ := json.Marshal(fact)
	outcomeHash := sha256.Sum256(outcome)
	fact.FactID += "-" + hex.EncodeToString(outcomeHash[:])
	path, err := trustirfacts.Persist(r.runDir, fact)
	if err != nil {
		return result, err
	}
	result.Fact, result.FactRef = fact, path
	return result, nil
}
