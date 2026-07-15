package codeql

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedQueryDiscriminates proves query generation works against real
// databases: a query generated purely from a TrustIR candidate flags the
// vulnerable DB and stays silent on the fixed DB — the same discrimination the
// hand-written spike query gave, but now derived from the located roles.
//
// Skipped unless the environment supplies:
//
//	CODEQL_BUNDLE     bundle dir (for the binary and the resolved rust libs)
//	CODEQL_DB_VULN    prebuilt DB of the vulnerable variant
//	CODEQL_DB_FIXED   prebuilt DB of the fixed variant
func TestGeneratedQueryDiscriminates(t *testing.T) {
	bundle := os.Getenv("CODEQL_BUNDLE")
	dbVuln := os.Getenv("CODEQL_DB_VULN")
	dbFixed := os.Getenv("CODEQL_DB_FIXED")
	if bundle == "" || dbVuln == "" || dbFixed == "" {
		t.Skip("set CODEQL_BUNDLE, CODEQL_DB_VULN, CODEQL_DB_FIXED to run")
	}
	engine := NewWithBin(filepath.Join(bundle, "codeql"))
	libs, err := RustLibrariesPath(bundle)
	if err != nil {
		t.Fatal(err)
	}

	query, err := GenerateBindingQuery(bindingCandidate())
	if err != nil {
		t.Fatal(err)
	}
	queryFile, err := WriteQueryPack(t.TempDir(), "generated_binding.ql", query, "codeql/rust-all")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		db   string
		want int
	}{
		{"vulnerable", dbVuln, 1},
		{"fixed", dbFixed, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, err := engine.Analyze(context.Background(), AnalyzeOptions{
				DBPath: tc.db, Queries: []string{queryFile}, AdditionalPacks: []string{libs},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != tc.want {
				t.Fatalf("%s: results=%d want %d (%+v)", tc.name, len(results), tc.want, results)
			}
		})
	}
}
