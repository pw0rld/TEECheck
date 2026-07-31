package twe

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// benchmarkIdentifiers are code identifiers that belong to benchmark cases,
// not to this scanner. A prompt that contains one is telling the model the
// answer to a case it is about to be measured on.
//
// This list is deliberately short and specific. It is not an attempt to
// enumerate every identifier in the corpus — the real guard would derive it
// from the datasets — but these are the ones that actually leaked.
var benchmarkIdentifiers = []string{
	"subkey_version",
	"check_update_version",
	"shdr_load_pub_key",
	"shdr_verify_signature",
}

// goComment matches a // line comment or a /* */ block. Prompt text is
// string literals; comments explaining the code are not sent anywhere and
// must not be flagged.
var goComment = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)

// promptSources are the files whose string literals become agent prompts.
func promptSources(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..", "internal")
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		base := filepath.Base(path)
		if base == "prompt.go" || strings.Contains(base, "prompt") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Skipf("cannot walk internal/: %v", err)
	}
	return out
}

// TestPrompts_DoNotSpellOutBenchmarkAnswers guards against the scanner
// reading a benchmark case's solution out of its own system prompt.
//
// Two prompts did. invariants/prompt.go illustrated "concrete, checkable
// steps" with «trace subkey_version from shdr_load_pub_key into
// check_update_version» — which is the CVE-2026-44362 answer, verbatim, in
// the system prompt of the stage that decides what to investigate. And on
// 2026-07-31, while fixing the ripgrep action, «(?i)subkey_version» was
// added to planner/prompt.go as the case-insensitivity example, using the
// identifier from the case under test as the sample pattern.
//
// Neither was noticed by reading. Both were found by an audit asking why a
// run's reasoning looked better than its evidence.
func TestPrompts_DoNotSpellOutBenchmarkAnswers(t *testing.T) {
	files := promptSources(t)
	if len(files) == 0 {
		t.Fatal("found no prompt sources — the walk is broken, not the prompts")
	}
	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Comments are documentation, not prompt text. Strip them so a note
		// explaining why an identifier matters is not mistaken for a leak.
		text := goComment.ReplaceAllString(string(body), " ")
		for _, id := range benchmarkIdentifiers {
			if strings.Contains(text, id) {
				t.Errorf("%s contains benchmark identifier %q outside a comment — a prompt "+
					"naming a case's own symbols hands the model the answer", path, id)
			}
		}
	}
}
