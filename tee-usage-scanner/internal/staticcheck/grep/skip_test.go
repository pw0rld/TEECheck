package grep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
)

// run searches root for one keyword and returns the paths it reported.
func run(t *testing.T, root, keyword string) []string {
	t.Helper()
	got, err := New().Run(context.Background(), staticcheck.CheckRequest{
		RepoRoot: root, Keywords: []string{keyword},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var paths []string
	for _, f := range got {
		paths = append(paths, f.Path)
	}
	return paths
}

func write(t *testing.T, root, rel string, body []byte) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// .git/index embeds source paths as plain strings inside binary records, so
// a keyword search matches them and returns raw bytes as evidence. On
// 2026-08-02, 96 such "findings" — NUL bytes and all — reached the verifier's
// and arbiter's prompts. It only became reachable when the scanner's root
// became a real checkout instead of a single-file fixture.
func TestRun_SkipsTheGitDirectory(t *testing.T) {
	root := t.TempDir()
	write(t, root, "core/crypto/signed_hdr.c", []byte("void shdr_load_pub_key(void) {}\n"))
	write(t, root, ".git/index", append([]byte("DIRC\x00\x01\x03\x03core/crypto/signed_hdr.c\x00"), 0x00, 0xff))
	// A TEXT file inside .git, so this asserts the directory skip and not
	// the binary sniff — .git/index alone is caught by either guard, which
	// let a broken directory skip pass unnoticed.
	write(t, root, ".git/COMMIT_EDITMSG", []byte("fix signed_hdr rollback propagation\n"))

	for _, p := range run(t, root, "signed_hdr") {
		if strings.HasPrefix(p, ".git/") {
			t.Errorf("reported a finding inside .git: %s", p)
		}
	}
}

// A blocklist is a list of the places binaries were last found. The checkout
// also carries keys/, images and build output, so the rule that has to hold
// is about content, not location.
func TestRun_SkipsBinaryFilesAnywhere(t *testing.T) {
	root := t.TempDir()
	write(t, root, "keys/default_ta.bin", []byte("shdr_load_pub_key\x00\x01\x02\x03binary payload"))
	write(t, root, "core/crypto/signed_hdr.c", []byte("void shdr_load_pub_key(void) {}\n"))

	paths := run(t, root, "shdr_load_pub_key")
	for _, p := range paths {
		if strings.HasSuffix(p, ".bin") {
			t.Errorf("reported a finding from a binary file: %s", p)
		}
	}
	// The real source must still be found — the filter must not swallow it.
	found := false
	for _, p := range paths {
		if p == "core/crypto/signed_hdr.c" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the C source must still be searched, got %v", paths)
	}
}

// A NUL further into a large text file is not a reason to drop it, and a
// file shorter than the sniff window must not be misjudged.
func TestLooksBinary_ShortTextFileIsNotBinary(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.c", []byte("int main(void) { return 0; }\n"))
	f, err := os.Open(filepath.Join(root, "a.c"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	binary, err := looksBinary(f)
	if err != nil {
		t.Fatal(err)
	}
	if binary {
		t.Fatal("a short C file must not be judged binary")
	}
	// The sniff must rewind, or the search that follows starts mid-file.
	buf := make([]byte, 3)
	if _, err := f.Read(buf); err != nil || string(buf) != "int" {
		t.Fatalf("looksBinary must leave the file at offset 0, read %q (%v)", buf, err)
	}
}
