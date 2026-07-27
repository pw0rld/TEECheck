package symbolcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRepo(t *testing.T, rel, body string) string {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFileContainsSymbol_Present(t *testing.T) {
	root := writeRepo(t, "src/a.c", "int main(void) { return der_decode_sequence(); }\n")
	got, err := FileContainsSymbol(root, "src/a.c", "der_decode_sequence")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("want true for a symbol that is present")
	}
}

// The exact shape the 2026-07-27 audit found: a fabricated symbol that
// looks like a real one in the same file.
func TestFileContainsSymbol_AbsentLookalike(t *testing.T) {
	root := writeRepo(t, "src/a.c", "LTC_SET_ASN1(x);\nder_decode_sequence(y);\n")
	got, err := FileContainsSymbol(root, "src/a.c", "der_decode_sequence_flexi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("want false for a symbol that does not appear in the file")
	}
}

func TestFileContainsSymbol_CaseInsensitive(t *testing.T) {
	root := writeRepo(t, "src/a.c", "void TEE_Malloc(void);\n")
	got, err := FileContainsSymbol(root, "src/a.c", "tee_malloc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("want true — matching is case-insensitive")
	}
}

func TestFileContainsSymbol_AbsolutePath(t *testing.T) {
	root := writeRepo(t, "src/a.c", "int helper(void);\n")
	abs := filepath.Join(root, "src/a.c")
	got, err := FileContainsSymbol(root, abs, "helper")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("want true — an absolute path must not be re-joined to repoRoot")
	}
}

func TestFileContainsSymbol_MissingFile(t *testing.T) {
	root := t.TempDir()
	if _, err := FileContainsSymbol(root, "nope.c", "x"); err == nil {
		t.Fatal("want an error for a file that does not exist")
	}
}
