package trustirfacts

import (
	"context"
	"fmt"
	"os/exec"
)

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
	cloneCmd := exec.CommandContext(ctx, "git", "clone", "--quiet", repository, dest)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone %s: %w\n%s", repository, err, tail(out, 2000))
	}
	checkoutCmd := exec.CommandContext(ctx, "git", "checkout", "--quiet", revision)
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
