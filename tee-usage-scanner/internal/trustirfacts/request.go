package trustirfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// Operation identifies one fact-layer query this package knows how to run.
// Values are stable strings persisted verbatim in ToolFact.Operation, so an
// existing persisted fact stays interpretable even after the Go constant
// name changes.
type Operation string

// OperationRollbackVersionPropagation is the STATE/rollback family's only
// operation in this first slice: TWE-STATE-001, "does the claim producer
// propagate the rollback-relevant field into the struct the authority
// reads". Other families (Flow, Guard, Binding, Config, Design, Leakage)
// are not implemented yet — Run reports them as StatusUnsupported.
const OperationRollbackVersionPropagation Operation = "cpp.state.rollback_version_propagation"

// operationQueries maps each supported Operation to the thin-shell query
// file, relative to the query pack root (Request.QueryPackDir).
var operationQueries = map[Operation]string{
	OperationRollbackVersionPropagation: "state/RollbackVersionNotPropagated.ql",
}

// DefaultQueryPackDir is the checked-in query pack's conventional location,
// relative to the tee-usage-scanner module root. Request.QueryPackDir is
// required rather than defaulted internally (this package makes no
// assumption about the caller's working directory) — callers wire this
// constant in explicitly, the same way cmd/twescan wires "knowledge/twe" in
// as its --knowledge default.
const DefaultQueryPackDir = "codeql/trustir/cpp"

// Request describes one fact-layer invocation: a repository pinned at a
// commit, the operation (query) to run, and where the checked-in query pack
// lives. RunDir is where the per-commit database, the materialized query
// pack, and the persisted ToolFact all land as explicit run artifacts (§23.3
// — the database is "not a cache side effect").
type Request struct {
	RunDir       string
	Repository   string
	Commit       string
	Operation    Operation
	QueryPackDir string

	// ExtraPATH is prepended to PATH for the database build, for parity with
	// codeql.CreateDBOptions.ExtraPATH. The C/C++ extractor under
	// --build-mode=none does not compile the tree (§23.7), so this is
	// normally unnecessary — it exists for forward compatibility with a
	// future build mode that does need a compiler on PATH.
	ExtraPATH string

	// Exec routes this package's own subprocesses — the git clone and
	// checkout that build the database's source tree — through the
	// recording chokepoint. The CodeQL subprocesses are recorded by the
	// Engine, which carries its own executor.
	//
	// Request is the seam because it is already this package's single
	// input object and already carries per-call wiring that is not part
	// of the request's identity (ExtraPATH is the precedent). Like
	// ExtraPATH, Exec is deliberately absent from argumentsSHA256 and
	// factID: whether a run recorded its subprocesses says nothing about
	// what the query found, so wiring it in must not invalidate a fact or
	// miss a database cache hit.
	//
	// Nil means "clone, record nothing".
	Exec executor.Executor
}

func (r Request) validate() error {
	var missing []string
	if strings.TrimSpace(r.RunDir) == "" {
		missing = append(missing, "RunDir")
	}
	if strings.TrimSpace(r.Repository) == "" {
		missing = append(missing, "Repository")
	}
	if strings.TrimSpace(r.Commit) == "" {
		missing = append(missing, "Commit")
	}
	if strings.TrimSpace(string(r.Operation)) == "" {
		missing = append(missing, "Operation")
	}
	if strings.TrimSpace(r.QueryPackDir) == "" {
		missing = append(missing, "QueryPackDir")
	}
	if len(missing) > 0 {
		return fmt.Errorf("trustirfacts: request missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// argumentsSHA256 hashes the parts of the request that determine the
// query's outcome (repository, commit, operation — the fact table itself is
// a pure function of Repository in this slice, see facttable.go). It backs
// both ToolFact.ArgumentsSHA256 (§9.6/§6.4) and FactID, and is the cache key
// §23.3's acceptance criterion ("same repo+commit+operation+args → cache
// hit") is tested against.
func (r Request) argumentsSHA256() string {
	// A stable, minimal JSON encoding rather than fmt.Sprintf: field
	// ordering is fixed by struct order, and this format is easy to extend
	// (e.g. a future `scope` field) without silently changing existing
	// hashes for requests that do not use the new field.
	type hashed struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Operation  string `json:"operation"`
	}
	data, err := json.Marshal(hashed{Repository: r.Repository, Commit: r.Commit, Operation: string(r.Operation)})
	if err != nil {
		// json.Marshal on this struct of plain strings cannot fail.
		panic(fmt.Sprintf("trustirfacts: marshal hash input: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// factID is deterministic in (repository, commit, operation): the same
// request always names the same fact, which is what makes ToolFact
// persistence idempotent (see persist.go) rather than accumulating a new
// file per repeated call.
func (r Request) factID() string {
	return fmt.Sprintf("trustir-cpp-%s-%s", r.Operation, r.argumentsSHA256()[:16])
}
