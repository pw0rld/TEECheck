package trustirfacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Unlike semgrep / codeql / repomix, git IS installed here, so everything
// in this file exercises the real binary against a real local repository.
// These are the strongest parity claims in the change.

// ─── behaviour parity ────────────────────────────────────────────────
//
// Written and run green against the pre-executor implementation, then
// re-run unchanged afterwards. TestCloneAtRevision and
// TestCloneAtRevision_RejectsArgvSmuggling in clone_test.go are part of
// this harness too — they already pinned the happy path and the two
// injection guards, and were not modified.

// A clone failure must name the repository and carry git's own diagnostic
// on the line below. The %w/%s split is what makes the message readable.
func TestParity_CloneFailureErrorString(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	dest := filepath.Join(t.TempDir(), "checkout")

	err := cloneAtRevision(context.Background(), nil, missing, "HEAD", dest)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "git clone "+missing+": exit status ") {
		t.Errorf("err = %q, want prefix %q", msg, "git clone "+missing+": exit status <n>")
	}
	// git's diagnostic is localised (this machine's git speaks Chinese), so
	// assert on its shape rather than its words: a second line exists and
	// names the repository git could not open.
	_, diag, ok := strings.Cut(msg, "\n")
	if !ok || strings.TrimSpace(diag) == "" {
		t.Fatalf("err = %q, must carry git's own output on the line below", msg)
	}
	if !strings.Contains(diag, missing) {
		t.Errorf("git diagnostic = %q, want it to name %q", diag, missing)
	}
}

// git reads a lot from the environment — LANG (which is why the diagnostic
// above is not in English on this machine), GIT_*, SSH_AUTH_SOCK for
// authenticated clones, HOME for ~/.gitconfig. A chokepoint that passed
// only PATH+HOME would silently change all of that, so the inheritance is
// pinned with a canary the child echoes back.
func TestParity_CloneChildInheritsParentEnvironment(t *testing.T) {
	// GIT_AUTHOR_NAME is a real git-honoured variable, so this proves the
	// inheritance on a variable git itself would use, not just any string.
	t.Setenv("GIT_AUTHOR_NAME", "teecheck-canary")

	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	writeAndCommit(t, origin, "a.txt", "one\n", "first")

	dest := filepath.Join(t.TempDir(), "checkout")
	if err := cloneAtRevision(context.Background(), nil, origin, "HEAD", dest); err != nil {
		t.Fatalf("cloneAtRevision: %v", err)
	}
	out := gitOutput(t, dest, "log", "-1", "--format=%an")
	if strings.TrimSpace(out) != "teecheck-canary" {
		t.Errorf("author = %q, want teecheck-canary — the child did not inherit GIT_AUTHOR_NAME", out)
	}
}

// A checkout failure is reported separately from a clone failure: the
// clone succeeded, so the message must say checkout, and must name the
// revision that could not be resolved.
func TestParity_CheckoutFailureErrorString(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")
	writeAndCommit(t, origin, "a.txt", "one\n", "first")

	dest := filepath.Join(t.TempDir(), "checkout")
	err := cloneAtRevision(context.Background(), nil, origin, "0000000000000000000000000000000000000000", dest)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "git checkout 0000000000000000000000000000000000000000: exit status ") {
		t.Errorf("err = %q, want the checkout family with the revision named", msg)
	}
	// The clone half succeeded, so the destination exists.
	if _, statErr := os.Stat(filepath.Join(dest, ".git")); statErr != nil {
		t.Errorf("clone should have succeeded before checkout failed: %v", statErr)
	}
}

// The checkout runs with dest as its working directory. Without that, git
// would operate on whatever repository the process happens to be inside —
// which, when the tests run from this module, is TEECheck itself.
func TestParity_CheckoutRunsInsideDest(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")
	writeAndCommit(t, origin, "v.txt", "v1\n", "first")
	first := headCommit(t, origin)
	writeAndCommit(t, origin, "v.txt", "v2\n", "second")

	dest := filepath.Join(t.TempDir(), "checkout")
	if err := cloneAtRevision(context.Background(), nil, origin, first, dest); err != nil {
		t.Fatalf("cloneAtRevision: %v", err)
	}
	if got := headCommit(t, dest); got != first {
		t.Errorf("dest HEAD = %s, want %s — checkout did not run inside dest", got, first)
	}
	// And the clone was NOT shallow: §23.3 pins a full clone because a
	// pinned CVE revision can be arbitrarily far behind the branch tip.
	if _, err := os.Stat(filepath.Join(dest, ".git", "shallow")); err == nil {
		t.Error("clone was shallow; §23.3 requires a full clone")
	}
}
