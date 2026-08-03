package projectmap

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/observationlimits"
)

func sym(file string, line int, name string) artifacts.SymbolID {
	return artifacts.MakeSymbolID("cpp", file, line, name, "()")
}

// The measurement that motivated per-module size: OP-TEE's lib/ holds 898
// files named libmbedtls and libunw. The deleted keyword fingerprint never
// reported it, so every consumer treated vendored dependencies as
// first-party code and the architecture agent modelled them as project
// components.
func TestBuildModuleCards_ReportsSizePerModule(t *testing.T) {
	facts := artifacts.RepoFacts{Capsules: []artifacts.FunctionCapsule{
		{SymbolID: sym("core/crypto/x.c", 1, "a"), Module: "core/crypto"},
		{SymbolID: sym("core/crypto/y.c", 1, "b"), Module: "core/crypto"},
		{SymbolID: sym("lib/libmbedtls/z.c", 1, "c"), Module: "lib/libmbedtls"},
	}}
	byPath := map[string]artifacts.ModuleCard{}
	for _, c := range buildModuleCards(facts, map[string]int{"core/crypto": 2, "lib/libmbedtls": 898}) {
		byPath[c.Path] = c
	}
	if byPath["core/crypto"].FunctionCount != 2 {
		t.Errorf("core/crypto functions = %d, want 2", byPath["core/crypto"].FunctionCount)
	}
	if byPath["lib/libmbedtls"].FileCount != 898 {
		t.Errorf("lib/libmbedtls files = %d, want 898 — the number that says this is vendored",
			byPath["lib/libmbedtls"].FileCount)
	}
}

// Module edges come from resolved call edges by symbol id. Matching names
// instead would connect two same-named statics to each other's modules.
func TestBuildModuleCards_DerivesEdgesFromCallEdgesByID(t *testing.T) {
	loader := sym("core/crypto/signed_hdr.c", 262, "shdr_load_pub_key")
	caller := sym("core/kernel/ree_fs_ta.c", 298, "ree_fs_ta_open")
	facts := artifacts.RepoFacts{
		Capsules: []artifacts.FunctionCapsule{
			{SymbolID: loader, Module: "core/crypto"},
			{SymbolID: caller, Module: "core/kernel"},
		},
		CallEdges: []artifacts.CallEdge{{CallerID: caller, CalleeID: loader}},
	}
	byPath := map[string]artifacts.ModuleCard{}
	for _, c := range buildModuleCards(facts, nil) {
		byPath[c.Path] = c
	}
	if got := byPath["core/crypto"].CalledByModules; len(got) != 1 || got[0] != "core/kernel" {
		t.Errorf("core/crypto called_by = %v, want [core/kernel]", got)
	}
	if got := byPath["core/kernel"].CallsModules; len(got) != 1 || got[0] != "core/crypto" {
		t.Errorf("core/kernel calls = %v, want [core/crypto]", got)
	}
}

// A module calling itself is not a dependency. Recording it would make every
// module depend on itself and drown the edges that mean something.
func TestBuildModuleCards_SkipsSelfEdges(t *testing.T) {
	a := sym("core/crypto/x.c", 1, "a")
	b := sym("core/crypto/y.c", 1, "b")
	facts := artifacts.RepoFacts{
		Capsules:  []artifacts.FunctionCapsule{{SymbolID: a, Module: "core/crypto"}, {SymbolID: b, Module: "core/crypto"}},
		CallEdges: []artifacts.CallEdge{{CallerID: a, CalleeID: b}},
	}
	for _, c := range buildModuleCards(facts, nil) {
		if len(c.CallsModules) != 0 || len(c.CalledByModules) != 0 {
			t.Errorf("%s recorded a self edge: calls=%v called_by=%v", c.Path, c.CallsModules, c.CalledByModules)
		}
	}
}

// The baseline measured a 26 KB capsule. A fixed per-page count would put
// several of those in one observation; the split has to be on bytes.
func TestPaginate_SplitsByBytesNotCount(t *testing.T) {
	big := strings.Repeat("x", 20*1024)
	caps := []artifacts.FunctionCapsule{
		{SymbolID: "a", Name: big}, {SymbolID: "b", Name: big}, {SymbolID: "c", Name: big},
	}
	pages := paginate(caps)
	if len(pages) < 3 {
		t.Fatalf("three 20 KB capsules cannot share a %d-byte page, got %d page(s)",
			observationlimits.MaxBytes, len(pages))
	}
	for i, p := range pages {
		if n := pageBytes(p); n > observationlimits.MaxBytes {
			t.Errorf("page %d is %d bytes, over the %d cap", i, n, observationlimits.MaxBytes)
		}
	}
}

// A single capsule larger than the whole budget still has to be reachable.
// Dropping it would make the page set silently incomplete.
func TestPaginate_OversizeCapsuleGetsItsOwnPage(t *testing.T) {
	caps := []artifacts.FunctionCapsule{{SymbolID: "huge", Name: strings.Repeat("y", observationlimits.MaxBytes*2)}}
	pages := paginate(caps)
	if len(pages) != 1 || len(pages[0]) != 1 {
		t.Fatalf("an oversize capsule must still be paged, got %d page(s)", len(pages))
	}
}

// Every capsule must appear exactly once across the pages: the Planner's
// coverage ledger counts what it reviewed against what exists, and a capsule
// on no page can never be reviewed while one on two pages inflates the total.
func TestPaginate_CoversEveryCapsuleExactlyOnce(t *testing.T) {
	var caps []artifacts.FunctionCapsule
	for i := 0; i < 500; i++ {
		caps = append(caps, artifacts.FunctionCapsule{
			SymbolID: artifacts.SymbolID(strings.Repeat("s", i%40+1) + string(rune('a'+i%26))),
			Name:     strings.Repeat("n", i%300),
		})
	}
	seen := map[artifacts.SymbolID]int{}
	for _, p := range paginate(caps) {
		for _, c := range p {
			seen[c.SymbolID]++
		}
	}
	total := 0
	for _, n := range seen {
		if n != 1 {
			t.Fatalf("a capsule appears on %d pages", n)
		}
		total += n
	}
	if want := len(uniqueIDs(caps)); total != want {
		t.Errorf("paged %d capsules, want %d", total, want)
	}
}

func uniqueIDs(caps []artifacts.FunctionCapsule) map[artifacts.SymbolID]bool {
	out := map[artifacts.SymbolID]bool{}
	for _, c := range caps {
		out[c.SymbolID] = true
	}
	return out
}

// The card quotes the README rather than summarising it. A summary is an
// inference and would need an evidence state; a quote is a fact about the
// file, and the architecture agent can cite it.
func TestDocumentedPurpose_QuotesRatherThanSummarises(t *testing.T) {
	readme := "# OP-TEE Trusted OS\n\nThis git contains source code for the secure side\nimplementation of OP-TEE project.\n\nAll official documentation has moved.\n"
	got := documentedPurpose(readme)
	if !strings.Contains(got, "secure side") {
		t.Errorf("purpose = %q, want the README's own words", got)
	}
	if strings.HasPrefix(strings.TrimSpace(got), "#") {
		t.Errorf("purpose = %q, want the prose, not the heading marker", got)
	}
	if len(got) > purposeMaxBytes+8 {
		t.Errorf("purpose is %d bytes, want it bounded at %d", len(got), purposeMaxBytes)
	}
}

// A page reference the Planner cannot open is a page that does not exist,
// and the schema requires the path for exactly that reason.
func TestPageRef_CarriesAPath(t *testing.T) {
	ref := pageRef("core/crypto", 0, 12)
	if ref.Path == "" {
		t.Fatal("a page ref must name its file")
	}
	if !strings.Contains(ref.Path, "core") || !strings.HasSuffix(ref.Path, ".json") {
		t.Errorf("page path = %q, want a per-module json file", ref.Path)
	}
	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"path"`) {
		t.Errorf("page ref must serialise its path: %s", data)
	}
}

// ModuleOf and moduleOf in codeql/index/cpp/Symbols.ql must agree. The index
// assigns capsules to modules; this function counts files into them. If they
// disagree, a module's function count and its file count describe different
// sets, and the ratio a reader uses to spot vendored code means nothing.
//
// The expected values are what the query returned against the index fixture
// and against runs/run-b's OP-TEE database on 2026-08-03.
func TestModuleOf_AgreesWithTheIndexQuery(t *testing.T) {
	for rel, want := range map[string]string{
		"core/crypto/signed_hdr.c":        "core/crypto",
		"core/kernel/ree_fs_ta.c":         "core/kernel",
		"lib/libmbedtls/mbedtls/x.c":      "lib/libmbedtls",
		"core/arch/arm/plat-hikey/conf.h": "core/arch",
		"core/loader.c":                   "core",
		"core/dispatch.c":                 "core",
		"include/shdr.h":                  "include",
		"Makefile":                        ".",
	} {
		if got := ModuleOf(rel); got != want {
			t.Errorf("ModuleOf(%q) = %q, want %q", rel, got, want)
		}
	}
}
