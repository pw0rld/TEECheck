package codeql

import (
	"context"
	"os"
	"strings"
	"testing"
)

// The program index needs arbitrary result tables, and Analyze cannot give
// them: it shells out to `database analyze --format=sarifv2.1.0` and reads
// findings back out of SARIF, a shape with a place for a message and a
// location and nowhere to put an eight-column row.
func TestQueryTable_RejectsAMissingQueryBeforeShellingOut(t *testing.T) {
	e := NewWithBin("/nonexistent/codeql")
	_, err := e.QueryTable(context.Background(), QueryTableOptions{
		DBPath:    t.TempDir(),
		QueryFile: "/nonexistent/nope.ql",
	})
	if err == nil {
		t.Fatal("a missing query file must fail before the subprocess")
	}
	if !strings.Contains(err.Error(), "nope.ql") {
		t.Errorf("the error must name what was missing: %v", err)
	}
}

// A missing database is the other precondition. Both are checked here rather
// than left to CodeQL so the failure names the input, not an exit code.
func TestQueryTable_RejectsAMissingDatabase(t *testing.T) {
	e := NewWithBin("/nonexistent/codeql")
	_, err := e.QueryTable(context.Background(), QueryTableOptions{
		DBPath:    "/nonexistent/db",
		QueryFile: writeTempQuery(t),
	})
	if err == nil {
		t.Fatal("a missing database must fail before the subprocess")
	}
	if !strings.Contains(err.Error(), "/nonexistent/db") {
		t.Errorf("the error must name the database: %v", err)
	}
}

// decodeBQRS is the half of QueryTable that does not need CodeQL, so it is
// the half that can be tested everywhere. This payload is verbatim the shape
// `bqrs decode --format=json --result-set='#select'` produced against
// run-b's database on 2026-08-03 — the named form, the set alone.
func TestDecodeBQRS_FlattensTuplesToStrings(t *testing.T) {
	body := []byte(`{
	  "columns": [{"name":"symbol","kind":"String"}, {"name":"line","kind":"Integer"}],
	  "tuples": [["shdr_load_pub_key", 262], ["check_update_version", 86]]
	}`)
	rows, err := decodeBQRS(body)
	if err != nil {
		t.Fatalf("decodeBQRS: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("decoded %d rows, want 2", len(rows))
	}
	if rows[0][0] != "shdr_load_pub_key" || rows[0][1] != "262" {
		t.Errorf("row 0 = %v, want [shdr_load_pub_key 262] — numbers must arrive as strings", rows[0])
	}
}

// JSON numbers decode to float64, and %g renders 1234567 as "1.234567e+06".
// A byte offset in a large file passes that threshold easily, so an integer
// column has to be rendered as an integer or it silently becomes unusable
// exactly where the file is big enough to matter.
func TestDecodeBQRS_LargeIntegersDoNotBecomeExponents(t *testing.T) {
	body := []byte(`{
	  "columns": [{"name":"start_byte","kind":"Integer"}],
	  "tuples": [[1234567], [42322000], [262]]
	}`)
	rows, err := decodeBQRS(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1234567", "42322000", "262"}
	for i, w := range want {
		if rows[i][0] != w {
			t.Errorf("row %d = %q, want %q", i, rows[i][0], w)
		}
	}
}

// An empty result set is a legitimate answer, not an error. A query that
// matched nothing and a query that failed have to stay distinguishable, or
// every "the index found nothing" becomes unreadable.
func TestDecodeBQRS_EmptyResultIsNotAnError(t *testing.T) {
	rows, err := decodeBQRS([]byte(`{"columns": [], "tuples": []}`))
	if err != nil {
		t.Fatalf("an empty result set must decode cleanly: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("decoded %d rows from an empty result set", len(rows))
	}
}

// A payload with no tuples key at all is not a result set. It must not
// decode to zero rows: "the query matched nothing" and "this is not the
// shape we expected" are different answers, and only the first is evidence
// about the code.
func TestDecodeBQRS_MissingTuplesIsNotAnEmptyResult(t *testing.T) {
	_, err := decodeBQRS([]byte(`{"#select": {"tuples": []}}`))
	if err == nil {
		t.Fatal("the un-named map form must be rejected, not read as zero rows")
	}
	if !strings.Contains(err.Error(), "tuples") {
		t.Errorf("the error must name what was missing: %v", err)
	}
}

func writeTempQuery(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/probe.ql"
	if err := os.WriteFile(path, []byte("import cpp\nselect 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
