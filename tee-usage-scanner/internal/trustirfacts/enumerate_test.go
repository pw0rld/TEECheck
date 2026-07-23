package trustirfacts

import (
	"path/filepath"
	"testing"
)

// rollbackFixtureC mirrors the CVE-2026-44362 shape docs/design/
// C-fact-table-spike.md hand-verified: a producer that copies most fields
// of a subkey into an output struct but never assigns the version field,
// and an authority that later reads that field. Enumerate has no notion of
// "vulnerable" — it must simply find every real name a resolver can later
// check LLM output against.
const rollbackFixtureC = `
#include <stdint.h>

struct shdr_pub_key {
	uint32_t max_depth;
	uint32_t name_size;
	uint32_t uuid;
	uint32_t algo;
	uint32_t version;
};

// a comment containing a fake_function(with, args) that must NOT be enumerated
static int shdr_load_pub_key(struct shdr_subkey *subkey, struct shdr_pub_key *key)
{
	key->max_depth = subkey->max_depth;
	key->name_size = subkey->name_size;
	key->uuid = subkey->uuid;
	key->algo = subkey->algo;
	/* deliberately missing: key->version = subkey->subkey_version; */
	return 0;
}

int check_update_version(struct shdr_pub_key *pub_key)
{
	if (pub_key->version < get_min_version()) {
		return -1;
	}
	return 0;
}
`

func TestEnumerate_FindsFunctionsFieldsAndStructs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "core", "crypto", "signed_hdr.c"), rollbackFixtureC)

	cand, err := Enumerate(dir)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}

	wantFuncs := []string{"shdr_load_pub_key", "check_update_version", "get_min_version"}
	for _, name := range wantFuncs {
		if !functionNameSet(cand)[name] {
			t.Errorf("Functions missing %q; got %+v", name, cand.Functions)
		}
	}
	if functionNameSet(cand)["fake_function"] {
		t.Error("a call-shaped token inside a comment must not be enumerated")
	}

	if !stringSet(cand.Fields)["version"] {
		t.Errorf("Fields missing %q (from key->version); got %v", "version", cand.Fields)
	}
	if !stringSet(cand.Structs)["shdr_pub_key"] {
		t.Errorf("Structs missing %q; got %v", "shdr_pub_key", cand.Structs)
	}

	// Every keyword-shaped token from control flow (if) must be excluded.
	if functionNameSet(cand)["if"] {
		t.Error("the 'if' keyword must never be enumerated as a function candidate")
	}
}

func TestEnumerate_RecordsEvidenceFilesNotLines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.c"), "int foo(void) { return bar(); }\n")
	writeFile(t, filepath.Join(dir, "b.c"), "int bar(void) { return foo(); }\n")

	cand, err := Enumerate(dir)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	byName := map[string]FunctionCandidate{}
	for _, f := range cand.Functions {
		byName[f.Name] = f
	}
	foo, ok := byName["foo"]
	if !ok {
		t.Fatal("expected foo to be enumerated")
	}
	// foo is defined in a.c and called from b.c: both files are evidence.
	if len(foo.Files) != 2 {
		t.Errorf("foo.Files = %v, want 2 files (definition + call site)", foo.Files)
	}
	// FunctionCandidate carries no line number field at all — enumeration
	// must key candidates on name only (§23.4.1: no exact-line anchoring).
}

func TestEnumerate_SkipsGitDirAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "hooks", "pre-commit.c"), "int should_not_be_seen(void) { return 0; }\n")
	writeFile(t, filepath.Join(dir, "real.c"), "int should_be_seen(void) { return 0; }\n")

	cand, err := Enumerate(dir)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	names := functionNameSet(cand)
	if names["should_not_be_seen"] {
		t.Error(".git directory contents must not be enumerated")
	}
	if !names["should_be_seen"] {
		t.Error("expected should_be_seen to be enumerated")
	}
}

func TestEnumerate_IgnoresNonSourceExtensions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "README.md"), "call_me(x, y)\n")
	writeFile(t, filepath.Join(dir, "real.c"), "int real_fn(void) { return 0; }\n")

	cand, err := Enumerate(dir)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	names := functionNameSet(cand)
	if names["call_me"] {
		t.Error("a non-C/C++ file must not contribute candidates")
	}
	if !names["real_fn"] {
		t.Error("expected real_fn to be enumerated")
	}
}

func TestEnumerate_EmptyTreeReturnsEmptyCandidates(t *testing.T) {
	dir := t.TempDir()
	cand, err := Enumerate(dir)
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(cand.Functions) != 0 || len(cand.Fields) != 0 || len(cand.Structs) != 0 {
		t.Errorf("expected empty Candidates for an empty tree, got %+v", cand)
	}
}

// TestEnumerate_AgainstRealBenchmarkFixture proves the enumerator works on
// actual, non-synthetic C source: a real file the benchmark corpus checks
// in (teecheck-benchmark/datasets/CVE-2016-6129/vulnerable). This is a
// partial checkout (one file, not the full libtomcrypt tree the real
// pipeline would git-clone) — see this package's PR report for why that
// partial-checkout shape is NOT sufficient to test the full annotate
// pipeline end to end, only Enumerate's regex pass on one real file.
func TestEnumerate_AgainstRealBenchmarkFixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "teecheck-benchmark", "datasets", "CVE-2016-6129", "vulnerable")
	cand, err := Enumerate(root)
	if err != nil {
		t.Skipf("benchmark fixture not present at %s: %v", root, err)
	}
	if len(cand.Functions) == 0 {
		t.Skip("benchmark fixture present but empty (unexpected layout); not this test's concern")
	}
	if !functionNameSet(cand)["rsa_verify_hash_ex"] {
		t.Errorf("expected rsa_verify_hash_ex among enumerated functions from the real CVE-2016-6129 fixture; got %d functions", len(cand.Functions))
	}
}
