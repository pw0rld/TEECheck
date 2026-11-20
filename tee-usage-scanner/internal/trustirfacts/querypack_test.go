package trustirfacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkedInQueryPackDir resolves the real codeql/trustir/cpp pack relative
// to this test file, so materialize tests exercise the actual checked-in
// pack (qlpack.yml, common/GeneratedTrustFacts.qll, state/*.ql) rather than
// a synthetic stand-in — catching a drift between the two directly.
func checkedInQueryPackDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", DefaultQueryPackDir)
	if _, err := os.Stat(filepath.Join(dir, "qlpack.yml")); err != nil {
		t.Skipf("checked-in query pack not found at %s: %v", dir, err)
	}
	return dir
}

func TestMaterializeQueryPack_CopiesAndOverwritesGeneratedFacts(t *testing.T) {
	src := checkedInQueryPackDir(t)
	runDir := t.TempDir()
	req := Request{
		RunDir: runDir, Repository: "https://github.com/OP-TEE/optee_os", Commit: "abc",
		Operation: OperationRollbackVersionPropagation, QueryPackDir: src,
	}
	table := FactTable{
		ClaimProducers: []ClaimProducerFact{{Function: "shdr_load_pub_key", Role: "security_version"}},
	}

	packDir, queryFile, err := materializeQueryPack(runDir, src, req, table)
	if err != nil {
		t.Fatalf("materializeQueryPack: %v", err)
	}

	// The static qlpack.yml is copied verbatim.
	if _, err := os.Stat(filepath.Join(packDir, "qlpack.yml")); err != nil {
		t.Errorf("qlpack.yml not copied: %v", err)
	}
	// The query file exists at the returned path and is inside packDir.
	if _, err := os.Stat(queryFile); err != nil {
		t.Errorf("query file not found at %s: %v", queryFile, err)
	}
	if !strings.HasPrefix(queryFile, packDir) {
		t.Errorf("query file %s should live under packDir %s", queryFile, packDir)
	}
	// The checked-in source pack is untouched.
	srcGenerated, err := os.ReadFile(filepath.Join(src, "common", "GeneratedTrustFacts.qll"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(srcGenerated), "shdr_load_pub_key") {
		t.Fatal("checked-in query pack must never be mutated in place")
	}
	// The materialized copy has the rendered fact table, not the checked-in
	// none()-only interface contract.
	gotGenerated, err := os.ReadFile(filepath.Join(packDir, "common", "GeneratedTrustFacts.qll"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gotGenerated), `f.getName() = "shdr_load_pub_key"`) {
		t.Errorf("materialized GeneratedTrustFacts.qll missing rendered clause:\n%s", gotGenerated)
	}
}

func TestMaterializeQueryPack_UnknownOperation(t *testing.T) {
	src := checkedInQueryPackDir(t)
	runDir := t.TempDir()
	req := Request{RunDir: runDir, Repository: "r", Commit: "c", Operation: "no-such-operation", QueryPackDir: src}

	if _, _, err := materializeQueryPack(runDir, src, req, FactTable{}); err == nil {
		t.Fatal("expected an error for an operation with no registered query")
	}
}

func TestMaterializeQueryPack_MissingSourceDir(t *testing.T) {
	runDir := t.TempDir()
	req := Request{
		RunDir: runDir, Repository: "r", Commit: "c",
		Operation: OperationRollbackVersionPropagation, QueryPackDir: "does-not-exist",
	}
	if _, _, err := materializeQueryPack(runDir, filepath.Join(t.TempDir(), "missing"), req, FactTable{}); err == nil {
		t.Fatal("expected an error when the checked-in query pack directory does not exist")
	}
}

func TestMaterializeQueryPackKeepsDifferentTablesIsolated(t *testing.T) {
	src, dir := checkedInQueryPackDir(t), t.TempDir()
	req := Request{Repository: "test", Commit: "abc", Operation: OperationRollbackVersionPropagation, QueryPackDir: src}
	a, _, err := materializeQueryPack(dir, src, req, FactTable{RollbackFields: []string{"version"}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(a, "common", "GeneratedTrustFacts.qll"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := materializeQueryPack(dir, src, req, FactTable{RollbackFields: []string{"epoch"}})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different tables share a mutable query pack")
	}
	after, err := os.ReadFile(filepath.Join(a, "common", "GeneratedTrustFacts.qll"))
	if err != nil || string(before) != string(after) {
		t.Fatal("earlier query pack was overwritten")
	}
}
