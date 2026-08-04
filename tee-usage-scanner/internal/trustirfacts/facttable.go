package trustirfacts

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
)

// ClaimProducerFact is one isClaimProducer clause: a function that produces
// a claim-bearing value, and the claim_field_role (enum_registry.yml) it
// carries.
type ClaimProducerFact struct {
	Function string
	Role     string
}

// RollbackAuthorityFact is one isRollbackAuthority clause: a call that
// consumes a rollback-relevant value, and the authority_kind
// (enum_registry.yml) of that decision.
type RollbackAuthorityFact struct {
	Function string
	Kind     string
}

// FactTable is a deterministic, hand-populated set of
// codeql/trustir/cpp/common/GeneratedTrustFacts.qll clauses for one case.
//
// This is NOT the output of an LLM annotation → resolver pipeline — that
// pipeline is explicitly deferred (§23.2). It is the same kind of fixture
// docs/design/C-fact-table-spike.md hand-wrote to prove the consumption end
// works on C: entity IDENTITY only (which function, which field, which
// call), no vulnerability logic. The vuln/fixed differential is decided by
// whether the named function structurally writes the named field — that
// judgment lives in the .ql thin shell, not here, and the table is expected
// to be byte-identical whether it is rendered against the vulnerable or the
// fixed revision (the spike proved exactly this for CVE-2026-44362).
type FactTable struct {
	ClaimProducers      []ClaimProducerFact
	RollbackFields      []string
	ProducedStructs     []string
	RollbackAuthorities []RollbackAuthorityFact
}

// Empty reports whether the table has no clauses at all — every predicate
// would render as none(). Run treats an empty table as unsupported input
// rather than executing a query that can never match anything (§23.4.3: a
// predicate must be genuinely populated, never silently none() while
// claiming to work).
func (t FactTable) Empty() bool {
	return len(t.ClaimProducers) == 0 && len(t.RollbackFields) == 0 &&
		len(t.ProducedStructs) == 0 && len(t.RollbackAuthorities) == 0
}

// Render emits the full GeneratedTrustFacts.qll content for this table,
// replacing the checked-in interface contract's none() bodies with this
// table's clauses. The predicate shapes (names, parameter order, doc
// comments) are kept identical to
// codeql/trustir/cpp/common/GeneratedTrustFacts.qll on purpose: this is a
// materialized COPY of that file for one run, not a different module.
func (t FactTable) Render() string {
	var b strings.Builder
	b.WriteString("/**\n" +
		" * GeneratedTrustFacts.qll (C/C++) — MATERIALIZED PER RUN.\n" +
		" *\n" +
		" * Rendered by internal/trustirfacts (facttable.go) from a deterministic\n" +
		" * fact table, not by an LLM annotation pipeline (§23.2 of the merge design\n" +
		" * is still the checked-in interface contract this file implements).\n" +
		" */\n" +
		"import cpp\n\n" +
		"module GeneratedTrustFacts {\n")

	b.WriteString("  /** A function that produces a claim-bearing value consumed by a downstream authority. */\n")
	b.WriteString(renderPredicate("isClaimProducer", "Function f, string role", claimProducerClauses(t.ClaimProducers)))

	b.WriteString("  /** The rollback-relevant field the producer must propagate into its output. */\n")
	b.WriteString(renderPredicate("rollbackVersionField", "string field", stringSetClauses("field", t.RollbackFields)))

	b.WriteString("  /** The struct type the producer fills through its output-pointer param. */\n")
	b.WriteString(renderPredicate("producedStruct", "string typeName", stringSetClauses("typeName", t.ProducedStructs)))

	b.WriteString("  /** An authority point: a call that consumes a version/state field for a rollback decision. */\n")
	b.WriteString(renderPredicate("isRollbackAuthority", "FunctionCall c, string kind", rollbackAuthorityClauses(t.RollbackAuthorities)))

	b.WriteString("  /** Suppressors: none generated in this slice (§23.2 — annotation pipeline deferred). */\n")
	b.WriteString(renderPredicate("hasSuppressor", "Function f, string suppressor", nil))

	b.WriteString("}\n")
	return b.String()
}

// renderPredicate writes one `predicate name(sig) { body }` block. An empty
// clause list renders as none() — the honest statement that this predicate
// has no facts for this run, matching the checked-in interface contract's
// default (see codeql/trustir/cpp/common/GeneratedTrustFacts.qll).
func renderPredicate(name, sig string, clauses []string) string {
	body := "none()"
	if len(clauses) > 0 {
		body = "\n    " + strings.Join(clauses, " or\n    ") + "\n  "
	}
	return fmt.Sprintf("  predicate %s(%s) { %s }\n\n", name, sig, body)
}

func claimProducerClauses(facts []ClaimProducerFact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, fmt.Sprintf("f.getName() = %s and role = %s", qlString(f.Function), qlString(f.Role)))
	}
	return out
}

func rollbackAuthorityClauses(facts []RollbackAuthorityFact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, fmt.Sprintf("c.getTarget().getName() = %s and kind = %s", qlString(f.Function), qlString(f.Kind)))
	}
	return out
}

func stringSetClauses(varName string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprintf("%s = %s", varName, qlString(v)))
	}
	return out
}

// qlString renders a Go string as a CodeQL string literal. Inputs come from
// this package's own registry (below), not from untrusted input, but a
// literal embedded quote is escaped defensively rather than assumed absent.
func qlString(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// knownFactTables is the hand-authored fixture registry for this
// deterministic skeleton, keyed by normalized repository URL (normalizeRepo
// below). It has exactly one entry today: CVE-2026-44362 (OP-TEE subkey
// rollback), the case docs/design/C-fact-table-spike.md validated. A
// repository with no entry here is StatusUnsupported, not a faked empty
// success — see run.go.
//
// role/kind values are enum_registry.yml members (claim_field_role
// "security_version", authority_kind "state_restore_acceptance") — see
// facttable_test.go's TestKnownFactTablesUseRegisteredEnumValues, which
// loads the real registry and checks membership, matching §23's acceptance
// criterion "role 枚举与 enum_registry.yml 一致性有测试保证". This is a
// deliberate correction of the spike pack, which used ad hoc strings
// ("signed_subkey_pubkey", "subkey_version_rollback_check") not in the
// registry — exactly the class of drift §23.4.2 calls out as the v1 fatal
// bug.
var knownFactTables = map[string]FactTable{
	"github.com/op-tee/optee_os": {
		ClaimProducers: []ClaimProducerFact{
			{Function: "shdr_load_pub_key", Role: "security_version"},
		},
		RollbackFields:  []string{"version"},
		ProducedStructs: []string{"shdr_pub_key"},
		RollbackAuthorities: []RollbackAuthorityFact{
			{Function: "check_update_version", Kind: "state_restore_acceptance"},
		},
	},
}

// factTableFor looks up the fact table for a repository: an LLM-annotated
// table registered via SetFactTable (factsource.go) takes priority, falling
// through to the deterministic knownFactTables fixture when none is
// registered. ok is false when neither source has a table for the
// repository — Run maps that to StatusUnsupported. See factsource.go's doc
// comment for why the LLM and deterministic paths are wired this way
// instead of as a parameter on Run.
func factTableFor(repository string) (FactTable, bool) {
	key := normalizeRepo(repository)
	if t, ok := lookupLLMFactTable(key); ok {
		return t, true
	}
	t, ok := knownFactTables[key]
	return t, ok
}

// isLLMFactTable reports whether repository's table (if any) came from the
// LLM annotation pipeline rather than the deterministic fixture. Run uses
// this only to disclose provenance in ToolFact.CoverageGaps — it plays no
// part in factTableFor's own lookup order above.
func isLLMFactTable(repository string) bool {
	_, ok := lookupLLMFactTable(normalizeRepo(repository))
	return ok
}

// normalizeRepo delegates to codedb, which derives database directory names
// from the same normalization. Two copies could drift, and a drift there
// means a fact table keyed on one identity while the database it describes
// lives under another.
func normalizeRepo(repository string) string { return codedb.NormalizeRepo(repository) }
