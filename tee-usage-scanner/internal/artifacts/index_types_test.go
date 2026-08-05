package artifacts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// jsonTags returns every json field name a struct type declares, so a test
// can assert on the wire contract rather than on Go field names.
func jsonTags(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	if rt.Kind() != reflect.Struct {
		t.Fatalf("jsonTags wants a struct, got %s", rt.Kind())
	}
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

// (file, symbol) is not an identity in C/C++: two files can each hold a
// static function of the same name, and one C++ translation unit can hold
// overloads. A caller list keyed on the bare name connects call edges to
// whichever definition happened to be written last.
func TestMakeSymbolID_SeparatesSameNamedDefinitions(t *testing.T) {
	a := MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 262, "load", "(struct shdr *)")
	sameNameOtherFile := MakeSymbolID("cpp", "core/kernel/ree_fs_ta.c", 262, "load", "(struct shdr *)")
	overloadSameFile := MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 300, "load", "(int)")

	if a == sameNameOtherFile {
		t.Error("two static functions of the same name in different files must not share an id")
	}
	if a == overloadSameFile {
		t.Error("overloads must not share an id")
	}
	if a != MakeSymbolID("cpp", "core/crypto/signed_hdr.c", 262, "load", "(struct shdr *)") {
		t.Error("the same definition must produce the same id")
	}
}

// 01 must not decide where the danger is. A judgement field on a capsule
// would reintroduce the amplification chain under a new name: a
// lexical hit becomes a "candidate", the candidate becomes an asset, the
// asset becomes an invariant, and the invariant anchors on a comment.
func TestFunctionCapsule_CarriesNoVerdictFields(t *testing.T) {
	banned := []string{"risk", "priority", "candidate", "suspicious", "severity", "twe", "score"}
	for _, name := range jsonTags(t, FunctionCapsule{}) {
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("FunctionCapsule field %q contains %q — 01 states behaviour, it does not judge", name, b)
			}
		}
	}
}

// CodeQL's FieldAccess matches an assignment's left-hand side too, so a
// predicate named "reads" silently contains writes. A consumer comparing a
// producer's reads against a consumer's reads would be comparing the wrong
// sets and would not be able to tell.
func TestFunctionCapsule_FieldNamesMatchWhatIsProved(t *testing.T) {
	tags := jsonTags(t, FunctionCapsule{})
	has := func(want string) bool {
		for _, n := range tags {
			if n == want {
				return true
			}
		}
		return false
	}
	if has("reads_fields") {
		t.Error("reads_fields is a lie — FieldAccess includes assignment targets; use field_accesses")
	}
	for _, want := range []string{"field_accesses", "direct_field_writes"} {
		if !has(want) {
			t.Errorf("FunctionCapsule must declare %q, got %v", want, tags)
		}
	}
}

// Every capsule states the limits of its own lists, so "no callers" cannot
// be read as "never called" and an absent write cannot be read as "never
// written".
func TestFunctionCapsule_DeclaresItsScopes(t *testing.T) {
	var c FunctionCapsule
	if c.CallersScope() != ScopeDirectResolvedCallsOnly {
		t.Errorf("CallersScope = %q, want %q", c.CallersScope(), ScopeDirectResolvedCallsOnly)
	}
	if c.FieldWritesScope() != ScopeDirectAssignmentOnly {
		t.Errorf("FieldWritesScope = %q, want %q", c.FieldWritesScope(), ScopeDirectAssignmentOnly)
	}
}

// One global "complete" invites over-trust. Under --build-mode=none the
// symbol table is solid, the call graph is missing every indirect edge, and
// build reachability was never computed at all — a consumer that sees one
// word cannot tell which of those it is holding.
func TestIndexCapabilities_ArePerCapability(t *testing.T) {
	tags := jsonTags(t, IndexCapabilities{})
	for _, want := range []string{"symbols", "direct_calls", "field_accesses", "build_reachability"} {
		found := false
		for _, n := range tags {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("IndexCapabilities must report %q, got %v", want, tags)
		}
	}
	if strings.Contains(strings.Join(tags, ","), "complete") {
		t.Error("a single global completeness verdict is what per-capability reporting replaces")
	}
}

// A total count cannot answer "could anything unresolved reach this
// function?", so a missing caller stays weak evidence no matter how small
// the count. The enclosing symbol and the call expression are what make the
// question answerable at all.
func TestUnresolvedCall_CarriesEnoughToBeAnswerable(t *testing.T) {
	tags := jsonTags(t, UnresolvedCall{})
	for _, want := range []string{"enclosing_symbol_id", "file", "line", "resolution_kind"} {
		found := false
		for _, n := range tags {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("UnresolvedCall must carry %q, got %v", want, tags)
		}
	}
}

// projectmap derives module dependency edges from the call graph. Doing that
// from the per-capsule name lists would mean resolving callee names back to
// definitions — the guess SymbolID exists to prevent — so the edges have to
// survive in the index as edges.
func TestRepoFacts_KeepsTheCallGraph(t *testing.T) {
	f := RepoFacts{
		SchemaVersion: SchemaVersionRepoFactsV1,
		CallEdges: []CallEdge{{
			CallerID: "cpp:core/kernel/ree_fs_ta.c:298:ree_fs_ta_open()",
			CalleeID: "cpp:core/crypto/signed_hdr.c:262:shdr_load_pub_key()",
			File:     "core/kernel/ree_fs_ta.c", Line: 298, Resolution: ResolutionDirect,
		}},
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "call_edges") {
		t.Errorf("RepoFacts must serialise its call graph: %s", data)
	}
	var back RepoFacts
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.CallEdges) != 1 || back.CallEdges[0].Line != 298 {
		t.Errorf("call edges did not round trip: %+v", back.CallEdges)
	}
}

func TestProjectMap_RoundTrips(t *testing.T) {
	in := ProjectMap{
		SchemaVersion: SchemaVersionProjectMapV1,
		Repository: RepositoryCard{
			DocumentedPurpose: "OP-TEE Trusted OS",
			Languages:         []string{"c"},
			BuildTargets:      []string{"make"},
		},
		Modules: []ModuleCard{{
			Path: "lib/libmbedtls", FileCount: 898, FunctionCount: 4000,
			CalledByModules: []string{"core/crypto"},
		}},
		FunctionPages: []FunctionCardPageRef{{Module: "core/crypto", Page: 0, Count: 50, Path: "p.json"}},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ProjectMap
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Modules[0].FileCount != 898 {
		t.Errorf("module file count did not round trip: %+v", out.Modules[0])
	}
	if out.FunctionPages[0].Path != "p.json" {
		t.Error("a page reference without its file path cannot be fetched")
	}
}
