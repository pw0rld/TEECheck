package codeql

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestFixtureEndToEnd drives a real benchmark fixture through the whole M2
// path: assemble a compilable crate from the fixture's CodeQL harness + a
// variant's scan file, build a Rust database, run the TWE query, and check the
// SARIF discriminates vulnerable (1 finding) from fixed (0).
//
// Skipped unless the environment supplies a CodeQL bundle and cargo:
//
//	CODEQL_BUNDLE  directory containing the codeql binary and qlpacks
//	CARGO_BIN_DIR  (optional) dir with cargo, prepended to PATH for the build
func TestFixtureEndToEnd(t *testing.T) {
	bundle := os.Getenv("CODEQL_BUNDLE")
	if bundle == "" {
		t.Skip("set CODEQL_BUNDLE (and CARGO_BIN_DIR) to run the fixture end-to-end test")
	}
	engine := NewWithBin(filepath.Join(bundle, "codeql"))
	if !engine.Available() {
		t.Fatalf("codeql not available under %s", bundle)
	}
	libs, err := RustLibrariesPath(bundle)
	if err != nil {
		t.Fatal(err)
	}
	extraPATH := os.Getenv("CARGO_BIN_DIR")

	fixture := filepath.Join("..", "..", "benchmark", "cases", "TWE-BIND-0001")
	harness := filepath.Join(fixture, "codeql")
	query := filepath.Join("..", "..", "codeql", "queries", "binding", "missing_subject_binding.ql")

	for _, tc := range []struct {
		variant string
		want    int
	}{
		{"vulnerable", 1},
		{"fixed", 0},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			crate := t.TempDir()
			if err := AssembleFixtureCrate(harness, filepath.Join(fixture, tc.variant), []string{"src/registry.rs"}, crate); err != nil {
				t.Fatal(err)
			}
			// sanity: the assembled crate must compile
			if extraPATH != "" {
				build := exec.Command(filepath.Join(extraPATH, "cargo"), "build")
				build.Dir = crate
				if out, err := build.CombinedOutput(); err != nil {
					t.Fatalf("assembled crate did not compile: %v\n%s", err, out)
				}
			}
			db := filepath.Join(t.TempDir(), "db")
			if err := engine.CreateDatabase(context.Background(), CreateDBOptions{
				Language: "rust", SourceRoot: crate, DBPath: db, Overwrite: true, ExtraPATH: extraPATH,
			}); err != nil {
				t.Fatal(err)
			}
			results, err := engine.Analyze(context.Background(), AnalyzeOptions{
				DBPath: db, Queries: []string{query}, AdditionalPacks: []string{libs},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != tc.want {
				t.Fatalf("%s: results=%d want %d (%+v)", tc.variant, len(results), tc.want, results)
			}
			t.Logf("%s: %d result(s) — OK", tc.variant, len(results))
		})
	}
}
