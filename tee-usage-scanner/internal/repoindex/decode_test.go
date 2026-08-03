package repoindex

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// A static inline defined in a header is extracted once per translation unit
// that includes it. On OP-TEE that is 19,572 rows for 11,301 definitions —
// without the dedupe every module count is inflated by 73% and every page
// the Planner browses is mostly repeats of what it just read.
func TestDecodeSymbols_DedupesTranslationUnitRepeats(t *testing.T) {
	rows := [][]string{
		{"shdr_load_pub_key", "core/crypto/signed_hdr.c", "262", "struct shdr * shdr", "core/crypto"},
		{"shdr_load_pub_key", "core/crypto/signed_hdr.c", "262", "struct shdr * shdr", "core/crypto"},
		{"check_update_version", "core/kernel/ree_fs_ta.c", "86", "", "core/kernel"},
	}
	got := decodeSymbols(rows)
	if len(got) != 2 {
		t.Fatalf("decoded %d symbols, want 2 after dedupe: %+v", len(got), got)
	}
}

// Two files can each define a static function of the same name. If they
// collapse, every call edge to either is attributed to whichever won.
func TestDecodeSymbols_KeepsSameNamedDefinitionsApart(t *testing.T) {
	got := decodeSymbols([][]string{
		{"helper", "core/loader.c", "6", "int v", "core"},
		{"helper", "core/other.c", "4", "int v", "core"},
	})
	if len(got) != 2 {
		t.Fatalf("decoded %d symbols, want 2: %+v", len(got), got)
	}
	if got[0].SymbolID == got[1].SymbolID {
		t.Errorf("same-named statics collapsed onto %q", got[0].SymbolID)
	}
}

// The capsule's caller and callee lists are assembled from edges by id, not
// by name, so two same-named functions never inherit each other's callers.
func TestBuildCapsules_AttributesEdgesByIDNotName(t *testing.T) {
	symbols := decodeSymbols([][]string{
		{"helper", "core/loader.c", "6", "int v", "core"},
		{"helper", "core/other.c", "4", "int v", "core"},
		{"load_pub_key", "core/loader.c", "14", "struct pub_key * key", "core"},
	})
	edges := decodeCallEdges([][]string{
		{"load_pub_key", "core/loader.c", "14", "struct pub_key * key",
			"helper", "core/loader.c", "6", "int v", "core/loader.c", "17"},
	})

	capsules := buildCapsules(symbols, edges, nil)
	byID := map[artifacts.SymbolID]artifacts.FunctionCapsule{}
	for _, c := range capsules {
		byID[c.SymbolID] = c
	}

	loaderHelper := artifacts.MakeSymbolID("cpp", "core/loader.c", 6, "helper", "(int v)")
	otherHelper := artifacts.MakeSymbolID("cpp", "core/other.c", 4, "helper", "(int v)")

	if n := len(byID[loaderHelper].CalledBy); n != 1 {
		t.Errorf("core/loader.c helper has %d callers, want 1", n)
	}
	if n := len(byID[otherHelper].CalledBy); n != 0 {
		t.Errorf("core/other.c helper has %d callers, want 0 — it inherited the other definition's edge", n)
	}
}

// The two field columns must land in the two fields that describe them.
// Swapping them would leave a consumer comparing a producer's writes against
// a consumer's accesses without any way to notice.
func TestBuildCapsules_SplitsFieldColumns(t *testing.T) {
	symbols := decodeSymbols([][]string{
		{"load_pub_key", "core/loader.c", "14", "struct pub_key * key", "core"},
		{"fill_version", "core/dispatch.c", "11", "struct pub_key * key", "core"},
	})
	accesses := decodeFieldAccesses([][]string{
		{"load_pub_key", "core/loader.c", "14", "struct pub_key * key",
			"pub_key.max_depth,subkey.max_depth", "pub_key.max_depth"},
		{"fill_version", "core/dispatch.c", "11", "struct pub_key * key",
			"pub_key.version,subkey.subkey_version", ""},
	})

	byID := map[artifacts.SymbolID]artifacts.FunctionCapsule{}
	for _, c := range buildCapsules(symbols, nil, accesses) {
		byID[c.SymbolID] = c
	}

	load := byID[artifacts.MakeSymbolID("cpp", "core/loader.c", 14, "load_pub_key", "(struct pub_key * key)")]
	if len(load.FieldAccesses) != 2 {
		t.Errorf("load_pub_key accesses = %v, want two", load.FieldAccesses)
	}
	if len(load.DirectFieldWrites) != 1 || load.DirectFieldWrites[0] != "pub_key.max_depth" {
		t.Errorf("load_pub_key direct writes = %v, want [pub_key.max_depth]", load.DirectFieldWrites)
	}

	fill := byID[artifacts.MakeSymbolID("cpp", "core/dispatch.c", 11, "fill_version", "(struct pub_key * key)")]
	if len(fill.FieldAccesses) != 2 {
		t.Errorf("fill_version accesses = %v, want two", fill.FieldAccesses)
	}
	if len(fill.DirectFieldWrites) != 0 {
		t.Errorf("fill_version direct writes = %v, want none — memcpy is not an assignment", fill.DirectFieldWrites)
	}
}

// An empty column is no entries, not one empty entry. An empty string in a
// caller list would read downstream as a function with an unnamed caller.
func TestSplitList_EmptyColumnIsNoEntries(t *testing.T) {
	if got := splitList(""); len(got) != 0 {
		t.Errorf("splitList(\"\") = %v, want none", got)
	}
	if got := splitList(" a , b ,, a "); len(got) != 2 {
		t.Errorf("splitList = %v, want a and b deduped and trimmed", got)
	}
}

// The counts have to be checkable against each other, or a query that
// silently matched nothing reads as a repository with no indirect calls.
func TestDecodeCallSiteCounts_ReadsBothRows(t *testing.T) {
	total, resolved, err := decodeCallSiteCounts([][]string{{"total", "4"}, {"resolved", "3"}})
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || resolved != 3 {
		t.Errorf("total=%d resolved=%d, want 4 and 3", total, resolved)
	}
}

func TestDecodeCallSiteCounts_MissingRowIsAnError(t *testing.T) {
	if _, _, err := decodeCallSiteCounts([][]string{{"total", "4"}}); err == nil {
		t.Error("a counts result missing the resolved row must fail, not default to zero")
	}
}
