package repoindex

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// lang is the SymbolID language tag. One language for now; the tag is in the
// id so a future extractor's symbols cannot silently share an id with a C++
// definition at the same file and line.
const lang = "cpp"

// splitList turns a comma-joined CodeQL concat column into a slice.
//
// An empty column is no entries, not one empty entry: an empty string in a
// caller list reads downstream as a function with an unnamed caller, which
// is worse than an empty list because it looks like information.
func splitList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

// signature normalises CodeQL's parameter string into the parenthesised form
// the SymbolID carries, so "int v" and "(int v)" cannot produce two ids for
// one definition.
func signature(paramString string) string {
	return "(" + strings.TrimSpace(paramString) + ")"
}

func symbolIDOf(name, file, line, paramString string) artifacts.SymbolID {
	return artifacts.MakeSymbolID(lang, strings.TrimSpace(file), atoi(line),
		strings.TrimSpace(name), signature(paramString))
}

// decodeSymbols converts Symbols.ql rows, deduped by SymbolID.
//
// The dedupe is not an optimisation. A static inline defined in a header is
// extracted once per translation unit that includes it; on OP-TEE that is
// 19,572 rows for 11,301 definitions, and without it every module count is
// inflated by 73% and every page the Planner browses is mostly repeats.
func decodeSymbols(rows [][]string) []artifacts.Symbol {
	const wantCols = 5
	byID := make(map[artifacts.SymbolID]artifacts.Symbol, len(rows))
	for _, r := range rows {
		if len(r) < wantCols {
			continue
		}
		name, file := strings.TrimSpace(r[0]), strings.TrimSpace(r[1])
		if name == "" || file == "" {
			continue
		}
		id := symbolIDOf(r[0], r[1], r[2], r[3])
		byID[id] = artifacts.Symbol{
			SymbolID:  id,
			Name:      name,
			File:      file,
			StartLine: atoi(r[2]),
			Signature: signature(r[3]),
			Module:    strings.TrimSpace(r[4]),
		}
	}
	out := make([]artifacts.Symbol, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	sortSymbols(out)
	return out
}

func sortSymbols(s []artifacts.Symbol) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].File != s[j].File {
			return s[i].File < s[j].File
		}
		if s[i].StartLine != s[j].StartLine {
			return s[i].StartLine < s[j].StartLine
		}
		return s[i].Name < s[j].Name
	})
}

// decodeCallEdges converts CallEdges.ql rows. Both ends are resolved to
// SymbolIDs here, which is what keeps two same-named definitions from
// inheriting each other's callers.
func decodeCallEdges(rows [][]string) []artifacts.CallEdge {
	const wantCols = 10
	seen := map[string]bool{}
	out := make([]artifacts.CallEdge, 0, len(rows))
	for _, r := range rows {
		if len(r) < wantCols {
			continue
		}
		e := artifacts.CallEdge{
			CallerID:   symbolIDOf(r[0], r[1], r[2], r[3]),
			CalleeID:   symbolIDOf(r[4], r[5], r[6], r[7]),
			File:       strings.TrimSpace(r[8]),
			Line:       atoi(r[9]),
			Resolution: artifacts.ResolutionDirect,
		}
		key := string(e.CallerID) + "\x00" + string(e.CalleeID) + "\x00" + e.File + "\x00" + strconv.Itoa(e.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].CalleeID < out[j].CalleeID
	})
	return out
}

// decodeUnresolvedCalls converts UnresolvedCalls.ql rows.
func decodeUnresolvedCalls(rows [][]string) []artifacts.UnresolvedCall {
	const wantCols = 8
	out := make([]artifacts.UnresolvedCall, 0, len(rows))
	for _, r := range rows {
		if len(r) < wantCols {
			continue
		}
		kind := strings.TrimSpace(r[7])
		switch kind {
		case artifacts.ResolutionIndirect, artifacts.ResolutionMacro, artifacts.ResolutionUnknown:
		default:
			kind = artifacts.ResolutionUnknown
		}
		out = append(out, artifacts.UnresolvedCall{
			EnclosingSymbolID: symbolIDOf(r[0], r[1], r[2], r[3]),
			File:              strings.TrimSpace(r[4]),
			Line:              atoi(r[5]),
			Expression:        strings.TrimSpace(r[6]),
			ResolutionKind:    kind,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// fieldAccess is one function's two field columns, keyed by SymbolID.
type fieldAccess struct {
	Accesses     []string
	DirectWrites []string
}

// decodeFieldAccesses converts FieldAccesses.ql rows into a lookup keyed by
// SymbolID. The two columns stay separate all the way through: merging them
// is the mistake the query's own doc comment exists to prevent.
func decodeFieldAccesses(rows [][]string) map[artifacts.SymbolID]fieldAccess {
	const wantCols = 6
	out := make(map[artifacts.SymbolID]fieldAccess, len(rows))
	for _, r := range rows {
		if len(r) < wantCols {
			continue
		}
		out[symbolIDOf(r[0], r[1], r[2], r[3])] = fieldAccess{
			Accesses:     splitList(r[4]),
			DirectWrites: splitList(r[5]),
		}
	}
	return out
}

// decodeCallSiteCounts reads the total and resolved call-site counts.
//
// A missing row is an error rather than a zero. Zero is a legitimate answer
// for a repository, so defaulting to it would make a query that silently
// matched nothing indistinguishable from a repository with no indirect
// calls — and every "no callers" answer downstream inherits that.
func decodeCallSiteCounts(rows [][]string) (total, resolved int, err error) {
	var haveTotal, haveResolved bool
	for _, r := range rows {
		if len(r) < 2 {
			continue
		}
		switch strings.TrimSpace(r[0]) {
		case "total":
			total, haveTotal = atoi(r[1]), true
		case "resolved":
			resolved, haveResolved = atoi(r[1]), true
		}
	}
	if !haveTotal || !haveResolved {
		return 0, 0, fmt.Errorf("call-site counts incomplete (total=%t resolved=%t): "+
			"a missing count is not a zero count", haveTotal, haveResolved)
	}
	return total, resolved, nil
}

// buildCapsules assembles one capsule per symbol from the edges and the
// field columns.
//
// Callers and callees come from the edge list by id. Building them from the
// per-row name strings instead would mean resolving a callee name back to a
// definition, which is the guess SymbolID exists to prevent: on a repository
// with two static helpers of the same name, one of them would inherit the
// other's callers and nothing downstream could tell.
func buildCapsules(
	symbols []artifacts.Symbol,
	edges []artifacts.CallEdge,
	accesses map[artifacts.SymbolID]fieldAccess,
) []artifacts.FunctionCapsule {
	callers := map[artifacts.SymbolID][]artifacts.SymbolID{}
	callees := map[artifacts.SymbolID][]artifacts.SymbolID{}
	for _, e := range edges {
		callers[e.CalleeID] = appendUnique(callers[e.CalleeID], e.CallerID)
		callees[e.CallerID] = appendUnique(callees[e.CallerID], e.CalleeID)
	}

	out := make([]artifacts.FunctionCapsule, 0, len(symbols))
	for _, s := range symbols {
		fa := accesses[s.SymbolID]
		out = append(out, artifacts.FunctionCapsule{
			SymbolID:          s.SymbolID,
			Name:              s.Name,
			Module:            s.Module,
			File:              s.File,
			Line:              s.StartLine,
			CalledBy:          callers[s.SymbolID],
			Calls:             callees[s.SymbolID],
			FieldAccesses:     fa.Accesses,
			DirectFieldWrites: fa.DirectWrites,
		})
	}
	return out
}

func appendUnique(list []artifacts.SymbolID, v artifacts.SymbolID) []artifacts.SymbolID {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	list = append(list, v)
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}
