package citations

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, repo, rel, body string) string {
	t.Helper()
	full := filepath.Join(repo, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestCitedBytes_ValidAndResolved(t *testing.T) {
	c := CitedBytes{File: "x.rs", StartLine: 1, EndLine: 3}
	if !c.Valid() {
		t.Error("Valid()=false on a complete input")
	}
	if c.Resolved() {
		t.Error("Resolved()=true before Resolve")
	}

	bad := CitedBytes{File: "x.rs", StartLine: 0, EndLine: 1}
	if bad.Valid() {
		t.Error("Valid()=true on StartLine=0")
	}
	bad2 := CitedBytes{File: "x.rs", StartLine: 5, EndLine: 3}
	if bad2.Valid() {
		t.Error("Valid()=true on EndLine < StartLine")
	}
}

func TestResolve_HappyPath(t *testing.T) {
	repo := t.TempDir()
	body := "line1\nline2\nline3 with content\nline4\n"
	writeFile(t, repo, "src/x.rs", body)

	c, err := Resolve(CitedBytes{
		File: "src/x.rs", StartLine: 2, EndLine: 3,
	}, repo)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !c.Resolved() {
		t.Error("Resolved()=false after Resolve")
	}
	// Lines 2-3: "line2\nline3 with content\n"
	wantStart := int64(len("line1\n"))
	wantEnd := int64(len("line1\nline2\nline3 with content\n"))
	if c.StartByte != wantStart {
		t.Errorf("StartByte=%d want %d", c.StartByte, wantStart)
	}
	if c.EndByte != wantEnd {
		t.Errorf("EndByte=%d want %d", c.EndByte, wantEnd)
	}
	if c.SHA256 == "" || len(c.SHA256) != 64 {
		t.Errorf("SHA256=%q wrong shape", c.SHA256)
	}

	// Resolve is deterministic.
	c2, err := Resolve(CitedBytes{File: "src/x.rs", StartLine: 2, EndLine: 3}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if c2.SHA256 != c.SHA256 {
		t.Errorf("SHA256 not deterministic: %q vs %q", c.SHA256, c2.SHA256)
	}
}

func TestResolve_FileMissing(t *testing.T) {
	repo := t.TempDir()
	_, err := Resolve(CitedBytes{File: "nope.rs", StartLine: 1, EndLine: 1}, repo)
	if !errors.Is(err, ErrFileMissing) {
		t.Errorf("err=%v, want ErrFileMissing", err)
	}
}

func TestResolve_LineOutOfRange(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "x.rs", "only one line\n")

	_, err := Resolve(CitedBytes{File: "x.rs", StartLine: 5, EndLine: 7}, repo)
	if !errors.Is(err, ErrLineOutOfRange) {
		t.Errorf("err=%v, want ErrLineOutOfRange", err)
	}
}

func TestResolve_FileWithoutTrailingNewline(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "x.rs", "first\nsecond")

	c, err := Resolve(CitedBytes{File: "x.rs", StartLine: 2, EndLine: 2}, repo)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// "second" with no trailing \n
	if c.EndByte-c.StartByte != int64(len("second")) {
		t.Errorf("byte range len=%d want %d", c.EndByte-c.StartByte, len("second"))
	}
}

func TestValidate_HappyPath(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "x.rs", "a\nb\nc\n")

	resolved, _ := Resolve(CitedBytes{File: "x.rs", StartLine: 2, EndLine: 2}, repo)
	if err := Validate(resolved, repo); err != nil {
		t.Errorf("validate failed unexpectedly: %v", err)
	}
}

func TestValidate_DriftDetected(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "x.rs", "a\nb\nc\n")

	resolved, _ := Resolve(CitedBytes{File: "x.rs", StartLine: 2, EndLine: 2}, repo)

	// Modify the cited line in place — sha256 should mismatch.
	writeFile(t, repo, "x.rs", "a\nB-modified\nc\n")

	err := Validate(resolved, repo)
	if !errors.Is(err, ErrSHA256Mismatch) {
		t.Errorf("err=%v, want ErrSHA256Mismatch", err)
	}
}

func TestValidate_LegacyWithoutHash(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, repo, "x.rs", "a\nb\nc\n")

	// Legacy citation: no SHA256 / byte fields. Validate succeeds
	// as long as the file still exists and the line range is
	// resolvable — this is the back-compat path for hypotheses
	// written before the citation contract.
	legacy := CitedBytes{File: "x.rs", StartLine: 1, EndLine: 2}
	if err := Validate(legacy, repo); err != nil {
		t.Errorf("legacy validate: %v", err)
	}
}

func TestValidate_ReformatAroundCitationKeepsSHA(t *testing.T) {
	// Reformatting OUTSIDE the cited range must NOT trigger drift,
	// because the cited bytes themselves are unchanged (when the
	// edit doesn't touch our lines). Practically this means:
	// adding lines AFTER our range is fine; adding lines BEFORE
	// shifts our line numbers and we'd resolve to the wrong region.
	//
	// The contract: line numbers are human-facing; sha256 is the
	// machine source of truth. If line numbers shift, the citation
	// is stale by definition. This test pins the after-range case
	// where line numbers stay valid.
	repo := t.TempDir()
	writeFile(t, repo, "x.rs", "a\nb\nc\n")
	resolved, _ := Resolve(CitedBytes{File: "x.rs", StartLine: 1, EndLine: 1}, repo)

	// Add a line after the cited range.
	writeFile(t, repo, "x.rs", "a\nb\nc\nd-added\n")
	if err := Validate(resolved, repo); err != nil {
		t.Errorf("validate after appending unrelated line: %v", err)
	}
}

func TestResolve_RejectsInvalidInput(t *testing.T) {
	_, err := Resolve(CitedBytes{File: "", StartLine: 1, EndLine: 1}, "")
	if !errors.Is(err, ErrNotResolvable) {
		t.Errorf("err=%v, want ErrNotResolvable", err)
	}
}

func TestResolve_AbsolutePath(t *testing.T) {
	repo := t.TempDir()
	full := writeFile(t, repo, "x.rs", "hello\nworld\n")
	c, err := Resolve(CitedBytes{File: full, StartLine: 1, EndLine: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.SHA256, "") || c.SHA256 == "" {
		t.Errorf("SHA256 empty")
	}
}
