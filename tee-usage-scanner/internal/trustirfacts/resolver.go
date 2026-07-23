package trustirfacts

import (
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twe"
)

// UnresolvedAnnotation records one LLM-proposed annotation the resolver
// rejected, and why. §23.3's "resolver: 把标注的名字解析到真实符号，未解析的标记
// unresolved" is this type: every rejection resolveAnnotations makes is one
// of these, returned to the caller in AnnotationReport.Unresolved — never
// just dropped and forgotten (§23's task framing: "Unresolved annotations
// are dropped and recorded as unresolved — never silently kept").
type UnresolvedAnnotation struct {
	// Category is one of "claim_producer", "rollback_authority",
	// "rollback_field", "produced_struct" — the FactTable field the
	// annotation would have populated had it resolved.
	Category string
	// Value is the function/field/struct name the LLM proposed.
	Value string
	// Detail is the proposed role/kind, for categories that have one
	// (empty for rollback_field/produced_struct).
	Detail string
	// Reason is a short, human-readable rejection reason.
	Reason string
}

// resolveAnnotations verifies every entry the LLM proposed (resp) against
// two independent authorities and renders only what survives both into a
// FactTable:
//
//  1. the enumerated Candidates (cand) — does the named function/field/
//     struct exist in the source tree Enumerate scanned? This is the
//     "resolve the name to a real symbol" half of §23.3.
//  2. registry (knowledge/twe/definitions/enum_registry.yml) — is the
//     proposed role/kind a member of the right category? This is §23.4.2's
//     hard requirement: role/kind values come from the registry and only
//     the registry, checked here against the SAME loaded map the
//     deterministic fixture's own test (facttable_test.go's
//     TestKnownFactTablesUseRegisteredEnumValues) checks — never a second,
//     re-declared copy of the vocabulary.
//
// A resolved-but-duplicate entry (the LLM naming the same function/role
// pair twice) is silently deduplicated, not recorded as unresolved — it is
// not a rejection, just a redundant true statement.
func resolveAnnotations(resp annotationResponse, cand Candidates, registry twe.EnumRegistry) (FactTable, []UnresolvedAnnotation) {
	funcSet := functionNameSet(cand)
	fieldSet := stringSet(cand.Fields)
	structSet := stringSet(cand.Structs)
	claimRoles := stringSet(registry["claim_field_role"])
	authorityKinds := stringSet(registry["authority_kind"])

	var table FactTable
	var unresolved []UnresolvedAnnotation

	seenProducers := map[string]bool{}
	for _, p := range resp.ClaimProducers {
		name := strings.TrimSpace(p.Function)
		role := strings.TrimSpace(p.Role)
		if reason, ok := checkFunctionRole(name, role, funcSet, claimRoles, "claim_field_role"); !ok {
			unresolved = append(unresolved, UnresolvedAnnotation{"claim_producer", name, role, reason})
			continue
		}
		key := name + "\x00" + role
		if seenProducers[key] {
			continue
		}
		seenProducers[key] = true
		table.ClaimProducers = append(table.ClaimProducers, ClaimProducerFact{Function: name, Role: role})
	}

	seenAuthorities := map[string]bool{}
	for _, a := range resp.RollbackAuthorities {
		name := strings.TrimSpace(a.Function)
		kind := strings.TrimSpace(a.Kind)
		if reason, ok := checkFunctionRole(name, kind, funcSet, authorityKinds, "authority_kind"); !ok {
			unresolved = append(unresolved, UnresolvedAnnotation{"rollback_authority", name, kind, reason})
			continue
		}
		key := name + "\x00" + kind
		if seenAuthorities[key] {
			continue
		}
		seenAuthorities[key] = true
		table.RollbackAuthorities = append(table.RollbackAuthorities, RollbackAuthorityFact{Function: name, Kind: kind})
	}

	seenFields := map[string]bool{}
	for _, raw := range resp.RollbackFields {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if !fieldSet[v] {
			unresolved = append(unresolved, UnresolvedAnnotation{"rollback_field", v, "", "field name not found among enumerated member-access candidates"})
			continue
		}
		if seenFields[v] {
			continue
		}
		seenFields[v] = true
		table.RollbackFields = append(table.RollbackFields, v)
	}

	seenStructs := map[string]bool{}
	for _, raw := range resp.ProducedStructs {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if !structSet[v] {
			unresolved = append(unresolved, UnresolvedAnnotation{"produced_struct", v, "", "struct name not found among enumerated 'struct NAME' candidates"})
			continue
		}
		if seenStructs[v] {
			continue
		}
		seenStructs[v] = true
		table.ProducedStructs = append(table.ProducedStructs, v)
	}

	return table, unresolved
}

// checkFunctionRole validates one (function, role/kind) pair shared by the
// claim_producers and rollback_authorities categories.
func checkFunctionRole(name, value string, funcSet, allowed map[string]bool, category string) (reason string, ok bool) {
	switch {
	case name == "":
		return "empty function name", false
	case value == "":
		return "empty role/kind", false
	case !funcSet[name]:
		return "function name not found among enumerated candidates", false
	case !allowed[value]:
		return "value not in enum_registry.yml " + category, false
	default:
		return "", true
	}
}

func functionNameSet(cand Candidates) map[string]bool {
	out := make(map[string]bool, len(cand.Functions))
	for _, f := range cand.Functions {
		out[f.Name] = true
	}
	return out
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}
