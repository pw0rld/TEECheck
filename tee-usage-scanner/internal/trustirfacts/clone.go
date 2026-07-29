package trustirfacts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
)

// cloneTimeout and checkoutTimeout bound calls that previously had no
// bound of their own beyond the caller's context.
//
// The clone budget is deliberately large. §23.3 pins a FULL, unshallowed
// clone (repofetch's --depth 50 is unusable here because a pinned CVE
// revision can be arbitrarily far behind the branch tip), and the targets
// are large C/C++ projects, so a cold clone over a slow link is genuinely
// tens of minutes. An hour is the point past which the clone is wedged
// rather than slow. Checkout is a local operation on an already-fetched
// object database and gets a much smaller budget.
const (
	cloneTimeout    = 60 * time.Minute
	checkoutTimeout = 10 * time.Minute
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

// cloneAtRevision clones repository into dest and checks out revision. ex
// may be nil, in which case the commands still run but leave no record.
//
// Both guards below run BEFORE the executor is touched, so a rejected
// repository or revision emits no tool_call events at all — a stream that
// claimed a command ran when it never did would be worse than silence.
//
// This is the DB-build recipe §23.3/§23.7 pin as non-negotiable: a full
// (unshallowed) clone, then checkout — never a single-file or stub-header
// fixture, which the earlier C-feasibility spike measured at 0 functions
// extracted. Unshallowed matters specifically because repofetch.Fetch's
// shallow (--depth 50) clone is unsuitable here: a pinned CVE revision can
// be arbitrarily far behind the branch tip, and a shallow clone that does
// not contain it fails the checkout outright.
func cloneAtRevision(ctx context.Context, ex executor.Executor, repository, revision, dest string) error {
	if err := assertSafeGitArg("repository", repository); err != nil {
		return err
	}
	if err := assertSafeGitArg("revision", revision); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(repository), "ext::") {
		return fmt.Errorf("refusing ext:: transport (arbitrary command execution): %q", repository)
	}

	run := executor.OrLocal(ex)

	// "--" terminates option parsing so repository/dest can never be read as
	// flags even if the prefix check above is someday loosened. dest is ours.
	clone := run.Run(ctx, executor.Request{
		Name:    "git-clone",
		Command: "git",
		Args:    []string{"clone", "--quiet", "--", repository, dest},
		Profile: executor.Profile{
			Network:      executor.NetworkAllow,
			Write:        executor.WriteWorkspace,
			Timeout:      cloneTimeout,
			EnvAllowlist: executor.InheritedEnvNames(),
		},
	})
	if err := clone.Err(); err != nil {
		return fmt.Errorf("git clone %s: %w\n%s", repository, err, tail(clone.Combined(), 2000))
	}
	// For checkout the "--" goes AFTER the revision: it separates the tree-ish
	// from an (empty) pathspec, so "git checkout <rev> --" still switches to
	// <rev> rather than treating it as a pathspec. Option-smuggling on
	// revision is already blocked by the prefix check above.
	checkout := run.Run(ctx, executor.Request{
		Name:    "git-checkout",
		Command: "git",
		Args:    []string{"checkout", "--quiet", revision, "--"},
		WorkDir: dest,
		Profile: executor.Profile{
			// Checkout works from the object database the clone already
			// fetched; it needs no network.
			Network:      executor.NetworkNone,
			Write:        executor.WriteWorkspace,
			Timeout:      checkoutTimeout,
			EnvAllowlist: executor.InheritedEnvNames(),
		},
	})
	if err := checkout.Err(); err != nil {
		return fmt.Errorf("git checkout %s: %w\n%s", revision, err, tail(checkout.Combined(), 2000))
	}
	return nil
}

func tail(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return "..." + string(b[len(b)-n:])
}
