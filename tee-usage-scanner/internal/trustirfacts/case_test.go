package trustirfacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCaseRevisions_FixedRevisionFromCaseYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "case.yaml"), `{
		"repository": "https://example.com/repo",
		"vulnerable_revision": "vuln123",
		"fixed_revision": "fixed456"
	}`)

	got, err := LoadCaseRevisions(dir)
	if err != nil {
		t.Fatalf("LoadCaseRevisions: %v", err)
	}
	want := CaseRevisions{Repository: "https://example.com/repo", VulnerableRevision: "vuln123", FixedRevision: "fixed456"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestLoadCaseRevisions_FixedRevisionFromOracleYAML matches the ACTUAL shape
// of the present benchmark corpus (see teecheck-benchmark/datasets/
// CVE-2026-44362/{case,oracle}.yaml): fixed_revision lives in oracle.yaml,
// not case.yaml, contradicting §23.3's "case.yaml 的
// repository/vulnerable_revision/fixed_revision" — see case.go's doc
// comment on this survey correction.
func TestLoadCaseRevisions_FixedRevisionFromOracleYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "case.yaml"), `{
		"repository": "https://github.com/OP-TEE/optee_os",
		"vulnerable_revision": "a9386bf987d95374a6f7f4c7bcf850115e0e1a4e"
	}`)
	writeFile(t, filepath.Join(dir, "oracle.yaml"), `{
		"fixed_revision": "43ed01d216a9586e7e7591dff1f7fbf80923f93f"
	}`)

	got, err := LoadCaseRevisions(dir)
	if err != nil {
		t.Fatalf("LoadCaseRevisions: %v", err)
	}
	if got.FixedRevision != "43ed01d216a9586e7e7591dff1f7fbf80923f93f" {
		t.Errorf("FixedRevision = %q, want the oracle.yaml value", got.FixedRevision)
	}
	if got.Repository != "https://github.com/OP-TEE/optee_os" {
		t.Errorf("Repository = %q", got.Repository)
	}
}

func TestLoadCaseRevisions_MissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "case.yaml"), `{"repository": "https://example.com/repo"}`)
	if _, err := LoadCaseRevisions(dir); err == nil {
		t.Fatal("expected an error when vulnerable_revision is missing")
	}
}

func TestLoadCaseRevisions_NoCaseFile(t *testing.T) {
	if _, err := LoadCaseRevisions(t.TempDir()); err == nil {
		t.Fatal("expected an error when case.yaml is absent")
	}
}

// TestLoadCaseRevisions_RealCVE20264362Fixture reads the actual benchmark
// corpus entry the deterministic fact table (facttable.go) targets. Skips
// (rather than fails) when the corpus is not checked out alongside this
// module, matching internal/preprocessor/benchmark_corpus_test.go's
// existing pattern for the same sibling-directory dependency.
func TestLoadCaseRevisions_RealCVE20264362Fixture(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "teecheck-benchmark", "datasets", "CVE-2026-44362")
	if _, err := os.Stat(filepath.Join(dir, "case.yaml")); err != nil {
		t.Skipf("benchmark corpus not present at %s: %v", dir, err)
	}

	got, err := LoadCaseRevisions(dir)
	if err != nil {
		t.Fatalf("LoadCaseRevisions: %v", err)
	}
	if got.Repository == "" || got.VulnerableRevision == "" || got.FixedRevision == "" {
		t.Fatalf("expected all three fields populated, got %+v", got)
	}
	if _, ok := factTableFor(got.Repository); !ok {
		t.Errorf("no deterministic fact table registered for %q — facttable.go's knownFactTables key must match the real case.yaml repository", got.Repository)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
