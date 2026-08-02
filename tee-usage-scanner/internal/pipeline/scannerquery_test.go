package pipeline

import (
	"strings"
	"testing"
)

func has(terms []string, want string) bool {
	for _, t := range terms {
		if t == want {
			return true
		}
	}
	return false
}

// The questions the verifier actually asked on 2026-08-02. Each names the
// code it wants; the surrounding prose does not locate anything.
func TestSearchTerms_KeepsIdentifiersFromRealQuestions(t *testing.T) {
	cases := []struct{ question, want string }{
		{"Locate every definition of the SHDR_GET_SIZE macro", "SHDR_GET_SIZE"},
		{"Find the definition of struct shdr in signed_hdr.h", "signed_hdr.h"},
		{"Find every caller of shdr_verify_signature2 in the repo", "shdr_verify_signature2"},
		{"Search the ENTIRE repository for core/kernel/ree_fs_ta.c", "core/kernel/ree_fs_ta.c"},
		{"Does `check_update_version` receive a real version?", "check_update_version"},
	}
	for _, c := range cases {
		got := searchTerms(c.question)
		if !has(got, c.want) {
			t.Errorf("searchTerms(%q) = %v, want it to contain %q", c.question, got, c.want)
		}
	}
}

// The prose is what made the search a dragnet: "the", "of", "in" and "every"
// match most lines of most source files, so a question containing them
// matched most of a 3291-file checkout and produced an 80 MB answer.
func TestSearchTerms_DropsProse(t *testing.T) {
	got := searchTerms("Locate every definition of the SHDR_GET_SIZE macro in the repository and report each one")
	for _, unwanted := range []string{"the", "of", "in", "every", "and", "each", "report", "repository"} {
		if has(got, unwanted) {
			t.Errorf("searchTerms kept the prose word %q — that is what matched the whole repository: %v", unwanted, got)
		}
	}
}

// A question that names nothing searchable must produce no search at all.
// Answering with the whole repository is indistinguishable, to the asking
// agent, from a targeted result — and it displaces real evidence in the
// prompt.
func TestSearchTerms_NoIdentifierMeansNoSearch(t *testing.T) {
	for _, q := range []string{
		"Is this path reachable in the shipped configuration?",
		"Do you agree that the guard is sufficient here?",
		"",
	} {
		if got := searchTerms(q); len(got) != 0 {
			t.Errorf("searchTerms(%q) = %v, want none — nothing in it locates code", q, got)
		}
	}
}

// The refusal has to tell the asker how to ask again, or it just looks like
// a broken tool.
func TestNoSearchableTerm_ExplainsWhatWouldWork(t *testing.T) {
	for _, want := range []string{"shdr_load_pub_key", "not evidence"} {
		if !strings.Contains(noSearchableTerm, want) {
			t.Errorf("the refusal must contain %q:\n%s", want, noSearchableTerm)
		}
	}
}

// Repeats collapse, so a question mentioning a symbol three times does not
// weight it three times.
func TestSearchTerms_Deduplicates(t *testing.T) {
	got := searchTerms("shdr_load_pub_key calls shdr_load_pub_key; check shdr_load_pub_key")
	n := 0
	for _, g := range got {
		if g == "shdr_load_pub_key" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("term appears %d times, want 1: %v", n, got)
	}
}
