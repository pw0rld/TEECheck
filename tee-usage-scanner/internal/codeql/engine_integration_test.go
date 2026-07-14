package codeql

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestAnalyzeIntegration drives the real codeql binary against a prebuilt
// database. It is skipped unless the environment supplies the pieces, so the
// default `go test` stays hermetic:
//
//	CODEQL_BIN     path to the codeql executable
//	CODEQL_DB      path to a prebuilt database
//	CODEQL_QUERY   a query file/dir/suite to run
//	CODEQL_PACKS   (optional) additional pack search paths, comma separated
//	CODEQL_WANT    (optional) expected result count; asserted when set
func TestAnalyzeIntegration(t *testing.T) {
	bin := os.Getenv("CODEQL_BIN")
	db := os.Getenv("CODEQL_DB")
	query := os.Getenv("CODEQL_QUERY")
	if bin == "" || db == "" || query == "" {
		t.Skip("set CODEQL_BIN, CODEQL_DB, CODEQL_QUERY to run the integration test")
	}
	engine := NewWithBin(bin)
	if !engine.Available() {
		t.Fatalf("codeql not available at %q", bin)
	}
	opts := AnalyzeOptions{DBPath: db, Queries: []string{query}}
	if packs := os.Getenv("CODEQL_PACKS"); packs != "" {
		opts.AdditionalPacks = strings.Split(packs, ",")
	}
	results, err := engine.Analyze(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("analyze produced %d result(s)", len(results))
	if want := os.Getenv("CODEQL_WANT"); want != "" {
		n, err := strconv.Atoi(want)
		if err != nil {
			t.Fatalf("bad CODEQL_WANT %q", want)
		}
		if len(results) != n {
			t.Fatalf("results=%d want %d", len(results), n)
		}
	}
}
