package trustirfacts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
)

// These build a throwaway local git repository for tests that need a real
// checkout. internal/codedb has its own copy: unexported test helpers do not
// cross a package boundary, and a shared testing package for four functions
// would be a heavier dependency than the duplication it removes.

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeAndCommit(t *testing.T, dir, name, content, message string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "--quiet", "-m", message)
}

func headCommit(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v", err)
	}
	return strings.TrimRight(string(out), "\n")
}

// newTestDB is the database provider these tests run against. It is the real
// codedb.Manager over the fake engine, so the database path derivation, the
// cache marker and the checkout are the production ones — this package's
// tests are about what a fact says, and swapping in a stub provider would
// stop exercising the wiring they depend on.
func newTestDB(eng codedb.Engine) codedb.DatabaseProvider { return codedb.New(eng, nil) }
