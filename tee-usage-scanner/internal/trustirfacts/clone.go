package trustirfacts

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// assertSafeGitArg guards the values that reach git as positional arguments.
// repository and revision come from benchmark case/oracle YAML today —
// version-controlled and reviewed — but this is the boundary where an
// untrusted repo spec would otherwise reach git, so it is checked regardless
// of the current source's trust level.
//
// Two threats, both real for git specifically:
//   - a value starting with "-" is read by git as an option, not a positional
//     (argv flag smuggling) — e.g. a repository of "--upload-pack=..." ;
//   - git's ext:: transport runs an arbitrary command, so an "ext::sh -c ..."
//     repository is remote code execution, not just a bad clone.
//
// A scheme allowlist is deliberately not used: cloning a local path is a
// legitimate offline/CI case (this package's own tests rely on it), and
// revisions are tree-ish (a sha, but also "HEAD" or a tag), so an
// allowlist/hex regex would reject valid inputs while adding nothing the two
// checks below don't already cover.
func assertSafeGitArg(kind, v string) error {
	if v == "" {
		return fmt.Errorf("empty %s", kind)
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("refusing %s starting with '-' (argv flag smuggling): %q", kind, v)
	}
	return nil
}

// cloneAtRevision clones repository into dest and checks out revision.
//
// This is the DB-build recipe §23.3/§23.7 pin as non-negotiable: a full
// (unshallowed) clone, then checkout — never a single-file or stub-header
// fixture, which the earlier C-feasibility spike measured at 0 functions
// extracted. Unshallowed matters specifically because repofetch.Fetch's
// shallow (--depth 50) clone is unsuitable here: a pinned CVE revision can
// be arbitrarily far behind the branch tip, and a shallow clone that does
// not contain it fails the checkout outright.
func cloneAtRevision(ctx context.Context, repository, revision, dest string) error {
	if err := assertSafeGitArg("repository", repository); err != nil {
		return err
	}
	if err := assertSafeGitArg("revision", revision); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(repository), "ext::") {
		return fmt.Errorf("refusing ext:: transport (arbitrary command execution): %q", repository)
	}

	// "--" terminates option parsing so repository/dest can never be read as
	// flags even if the prefix check above is someday loosened. dest is ours.
	cloneCmd := exec.CommandContext(ctx, "git", "clone", "--quiet", "--", repository, dest)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone %s: %w\n%s", repository, err, tail(out, 2000))
	}
	// For checkout the "--" goes AFTER the revision: it separates the tree-ish
	// from an (empty) pathspec, so "git checkout <rev> --" still switches to
	// <rev> rather than treating it as a pathspec. Option-smuggling on
	// revision is already blocked by the prefix check above.
	checkoutCmd := exec.CommandContext(ctx, "git", "checkout", "--quiet", revision, "--")
	checkoutCmd.Dir = dest
	if out, err := checkoutCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git checkout %s: %w\n%s", revision, err, tail(out, 2000))
	}
	return nil
}

func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "..." + string(b[len(b)-n:])
}
