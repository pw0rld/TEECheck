package trustirfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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

// tweOperations binds a TWE id to the operation that answers it. This is the
// bridge the catalog's query_modules field was supposed to be: internal/twe
// declared that field, validated it non-empty, and nothing else read it,
// while all nineteen values named .ql files that exist only in the sibling
// tee-audit rust/javascript/go trees. The real vocabulary was here, in
// operationQueries, with no connection between the two — so the only way the
// fact layer got invoked was a model choosing it unprompted, which across
// four runs on CVE-2026-44362 happened once.
//
// The binding lives in this package rather than internal/twe because
// trustirfacts already imports twe (for the enum registry); the reverse would
// be an import cycle. It also belongs next to operationQueries: an entry here
// is a promise that Run will not report unsupported, and the two maps are
// checked against each other in both directions by twebinding_test.go —
// every bound operation must be executable, and every executable operation
// must be bound, because a query no TWE points at cannot be reached from the
// knowledge layer at all.
var tweOperations = map[string]Operation{
	"TWE-STATE-001": OperationRollbackVersionPropagation,
}

// OperationForTWE returns the fact-layer operation that answers tweID. The
// false return is a real answer — "this family has no executable query yet" —
// and callers must not substitute a guess for it.
func OperationForTWE(tweID string) (Operation, bool) {
	op, ok := tweOperations[tweID]
	return op, ok
}

// TWEForOperation is the inverse of OperationForTWE: a TWE id whose question
// this operation answers. The P4+ deterministic fact lane (internal/pipeline)
// uses it to tag its grounded CasePacks with the playbook the downstream
// Challenger should load for them. twebinding_test.go enforces a surjection
// between tweOperations and operationQueries in both directions — every bound
// operation is executable, and every executable operation is bound — so for
// any supported operation at least one TWE exists. The mapping is not a
// bijection: more than one TWE may answer the same operation, in which case
// the lexicographically smallest id wins, so the answer is stable across runs
// rather than depending on Go map iteration order. The false return is still
// handled rather than panicked, so a future unbound operation degrades to an
// untagged case instead of a crash.
func TWEForOperation(op Operation) (string, bool) {
	var matches []string
	for twe, o := range tweOperations {
		if o == op {
			matches = append(matches, twe)
		}
	}
	if len(matches) == 0 {
		return "", false
	}
	sort.Strings(matches)
	return matches[0], true
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

// SupportedOperations returns the operations this fact layer can actually
// execute, sorted for a stable prompt and a stable error message.
//
// It exists because the closed vocabulary was previously unknowable from
// outside: the planner's prompt carried one "e.g." value and nothing else,
// and neither the action handler nor Request.validate rejected anything
// else. A model therefore had two ways to fail — invent an operation that
// does not exist (observed 2026-07-27: "cpp.flow.bounds_check_consistency",
// which produced a persisted ToolFact for a query that was never run), or,
// having no idea what was legal, never call the action at all (observed
// 2026-07-29 across three runs, including one whose repository DID have a
// fact table). Publishing the list closes both.
func SupportedOperations() []Operation {
	out := make([]Operation, 0, len(operationQueries))
	for op := range operationQueries {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// SupportedOperationStrings is SupportedOperations as plain strings, for
// callers that render the vocabulary into prompts or error text.
func SupportedOperationStrings() []string {
	ops := SupportedOperations()
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = string(op)
	}
	return out
}

// IsSupportedOperation reports whether name is an operation this fact layer
// can execute. Callers should check before dispatching so an unknown value
// fails where the caller can still correct it, rather than becoming a
// persisted "unsupported" ToolFact for a query that never ran.
func IsSupportedOperation(name string) bool {
	_, ok := operationQueries[Operation(strings.TrimSpace(name))]
	return ok
}
