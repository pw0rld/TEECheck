package pipeline

import (
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/repofetch"
)

// A benchmark fixture lives inside the TEECheck working tree, so git reports
// TEECheck's own origin and HEAD for it. The run must be able to state the
// upstream coordinates the fixture was extracted from, or every downstream
// consumer keyed on (repository, commit) — the TrustIR known fact tables, the
// deterministic fact IDs — looks up the wrong project.
func TestResolveRepoIdentity_ExplicitOverridesDetected(t *testing.T) {
	cfg := config.Config{
		RepoURL: "https://github.com/OP-TEE/optee_os",
		Commit:  "99e8a8cc3db341d703b6779563af98491253960a",
	}
	fetch := repofetch.FetchResult{
		RepoURL: "git@github.com:pw0rld/TEECheck.git",
		Commit:  "d8093179ada0deadbeef",
	}
	repoURL, commit := resolveRepoIdentity(cfg, fetch)
	if repoURL != "https://github.com/OP-TEE/optee_os" {
		t.Errorf("repoURL = %q, want the explicitly supplied upstream URL", repoURL)
	}
	if commit != "99e8a8cc3db341d703b6779563af98491253960a" {
		t.Errorf("commit = %q, want the explicitly supplied upstream revision", commit)
	}
}

// With nothing supplied, the detected git metadata is the identity — the
// ordinary "scan this checkout" case must keep working.
func TestResolveRepoIdentity_FallsBackToDetected(t *testing.T) {
	fetch := repofetch.FetchResult{
		RepoURL:   "https://github.com/OP-TEE/optee_os",
		Commit:    "abc123",
		LocalPath: "/tmp/x",
	}
	repoURL, commit := resolveRepoIdentity(config.Config{}, fetch)
	if repoURL != "https://github.com/OP-TEE/optee_os" || commit != "abc123" {
		t.Errorf("got (%q, %q), want the detected values", repoURL, commit)
	}
}

// A detected value must still fill in a field the caller left blank, so a
// partial override (URL only) does not blank out the commit.
func TestResolveRepoIdentity_PartialOverride(t *testing.T) {
	cfg := config.Config{RepoURL: "https://github.com/OP-TEE/optee_os"}
	fetch := repofetch.FetchResult{RepoURL: "git@github.com:pw0rld/TEECheck.git", Commit: "detected123"}
	repoURL, commit := resolveRepoIdentity(cfg, fetch)
	if repoURL != "https://github.com/OP-TEE/optee_os" {
		t.Errorf("repoURL = %q, want the explicit one", repoURL)
	}
	if commit != "detected123" {
		t.Errorf("commit = %q, want the detected one (none was supplied)", commit)
	}
}

// When neither is available the identity falls back to the local path, so a
// run against a plain directory still has a non-empty repository label.
func TestResolveRepoIdentity_FallsBackToLocalPath(t *testing.T) {
	fetch := repofetch.FetchResult{LocalPath: "/srv/some/checkout"}
	repoURL, _ := resolveRepoIdentity(config.Config{}, fetch)
	if repoURL != "/srv/some/checkout" {
		t.Errorf("repoURL = %q, want the local path as the last-resort label", repoURL)
	}
}
