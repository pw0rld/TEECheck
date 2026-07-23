package trustirfacts

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCloneAtRevision proves the §23.3 build recipe (full clone + checkout,
// never a shallow/single-file/stub-header fixture) against a purely local
// git repository — no network, no CodeQL. It also proves the pin actually
// pins: a second commit exists on the branch tip, and checkout must land on
// the FIRST commit, not HEAD.
func TestCloneAtRevision(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")

	writeAndCommit(t, origin, "version.txt", "v1\n", "first commit")
	firstCommit := headCommit(t, origin)
	writeAndCommit(t, origin, "version.txt", "v2\n", "second commit")

	dest := filepath.Join(t.TempDir(), "checkout")
	if err := cloneAtRevision(context.Background(), origin, firstCommit, dest); err != nil {
		t.Fatalf("cloneAtRevision: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "version.txt"))
	if err != nil {
		t.Fatalf("read checked-out file: %v", err)
	}
	if string(got) != "v1\n" {
		t.Errorf("version.txt = %q, want %q (checkout must pin to the first commit, not HEAD)", got, "v1\n")
	}
}

func TestCloneAtRevision_BadRepositoryFailsFast(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "checkout")
	err := cloneAtRevision(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), "HEAD", dest)
	if err == nil {
		t.Fatal("expected an error cloning a nonexistent local repository")
	}
}

// ─── test helpers shared by this package's tests ─────────────────────

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
	return trimNewline(string(out))
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
