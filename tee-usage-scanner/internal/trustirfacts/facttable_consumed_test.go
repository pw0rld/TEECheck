package trustirfacts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// renderedPredicate matches one predicate in FactTable.Render()'s output,
// capturing its name and body. renderPredicate emits either
// `predicate N(sig) { none() }` or `predicate N(sig) { \n    clauses\n  }`.
var renderedPredicate = regexp.MustCompile(`(?s)predicate (\w+)\([^)]*\) \{ (.*?)\}\n`)

// qlComment matches a QL block comment or a line comment. Comments must be
// stripped before searching for a predicate reference: this test's first
// version searched the raw text and passed while the reference was deleted,
// because the surrounding doc comment still named the predicate. A mention
// is not a use.
var qlComment = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)

// queryPackText concatenates the executable text of every .ql and .qll in
// the pack, excluding comments and the generated facts file itself — a
// predicate referenced only by its own declaration is the case under test.
func queryPackText(t *testing.T, packDir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(packDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Base(path) == "GeneratedTrustFacts.qll" {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".ql" && ext != ".qll" {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		b.Write(body)
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", packDir, err)
	}
	return qlComment.ReplaceAllString(b.String(), " ")
}

// TestKnownFactTables_EveryMaterializedFactIsConsumedByAQuery is the
// mechanized form of the defect that hid inside the one thin shell this
// project has.
//
// FactTable.Render() materialized `producedStruct(string typeName)` with a
// real value ("shdr_pub_key" for the OP-TEE entry) into every run's
// GeneratedTrustFacts.qll, and RollbackVersionNotPropagated.ql referenced it
// nowhere: writesOutputField matched on field NAME alone, so an assignment
// to any field called "version" on any type anywhere in the producer
// suppressed the finding. A fact that reaches the database and binds nothing
// is not evidence — it is a false negative waiting for an unrelated local
// variable.
//
// A predicate rendered as `none()` is exempt: an empty fact set genuinely
// has nothing to consume. hasSuppressor is the intended case, and its doc
// comment in the checked-in .qll says so ("Always `none()` until the
// annotation pipeline lands"). If a future fact table starts populating it,
// this test starts requiring a consumer — which is the point.
func TestKnownFactTables_EveryMaterializedFactIsConsumedByAQuery(t *testing.T) {
	packDir := checkedInQueryPackDir(t)
	pack := queryPackText(t, packDir)

	for repo, table := range knownFactTables {
		matches := renderedPredicate.FindAllStringSubmatch(table.Render(), -1)
		if len(matches) == 0 {
			t.Fatalf("%s: parsed no predicates out of Render() — the regex and "+
				"renderPredicate's format have drifted apart", repo)
		}
		for _, m := range matches {
			name, body := m[1], strings.TrimSpace(m[2])
			if body == "none()" {
				continue
			}
			if !strings.Contains(pack, name) {
				t.Errorf("%s: fact table materializes %s with a non-empty body (%s) but no "+
					"query in %s references it — the fact reaches the database and binds nothing",
					repo, name, body, packDir)
			}
		}
	}
}

// The comment stripping is the load-bearing part of the test above — without
// it the check degrades from "is referenced" to "is mentioned", which is how
// its first version passed a fire drill it should have failed.
func TestQLCommentStripping(t *testing.T) {
	src := "/** producedStruct is materialized but unused */\n" +
		"predicate p() { isClaimProducer(f, r) } // producedStruct again\n"
	got := qlComment.ReplaceAllString(src, " ")
	if strings.Contains(got, "producedStruct") {
		t.Fatalf("comment text survived stripping: %q", got)
	}
	if !strings.Contains(got, "isClaimProducer") {
		t.Fatalf("executable text was stripped: %q", got)
	}
}

// The exemption must stay narrow: a predicate is skipped only because its
// rendered body really is none(). If renderPredicate's empty form ever
// changes, the test above would silently start skipping populated facts.
func TestRenderPredicate_EmptyBodyIsExactlyNone(t *testing.T) {
	got := renderPredicate("p", "string x", nil)
	if !strings.Contains(got, "{ none() }") {
		t.Fatalf("renderPredicate with no clauses = %q; the consumed-fact test "+
			"recognises an empty fact set by the exact text \"none()\"", got)
	}
	populated := renderPredicate("p", "string x", []string{`x = "v"`})
	if strings.Contains(populated, "none()") {
		t.Fatalf("renderPredicate with clauses = %q, must not contain none()", populated)
	}
}
