package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

const (
	testRepo   = "https://github.com/OP-TEE/optee_os"
	testCommit = "a9386bf987d95374a6f7f4c7bcf850115e0e1a4e"
)

// markCheckout fakes a completed checkout at the path trustirfacts.SourceDir
// names, without cloning anything.
func markCheckout(t *testing.T, runDir, repo, commit string) string {
	t.Helper()
	dir := trustirfacts.SourceDir(runDir, repo, commit)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".trustirfacts-src-cloned"), []byte(commit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An existing checkout is reused, and it is what every stage reads. For a
// benchmark case the two trees differ by 3290 files, and the missing ones
// include the caller the fact layer locates.
func TestAcquireSourceScope_ReusesAnExistingCheckout(t *testing.T) {
	runDir := t.TempDir()
	want := markCheckout(t, runDir, testRepo, testCommit)

	got, pinned := acquireSourceScope(context.Background(), nil, runDir,
		testRepo, testCommit, "/fixtures/CVE-2026-44362/vulnerable")
	if !pinned {
		t.Error("pinned = false, want true — the checkout is present")
	}
	if got != want {
		t.Fatalf("root = %q, want the checkout %q", got, want)
	}
}

// No pinned identity: nothing to check out, and the run must proceed against
// the named target rather than failing.
func TestAcquireSourceScope_NoIdentityMeansTargetDirectory(t *testing.T) {
	fallback := "/some/local/dir"
	got, pinned := acquireSourceScope(context.Background(), nil, t.TempDir(), "", "", fallback)
	if pinned || got != fallback {
		t.Fatalf("root=%q pinned=%v, want the target directory and pinned=false", got, pinned)
	}
	if got, _ := acquireSourceScope(context.Background(), nil, t.TempDir(), testRepo, "", fallback); got != fallback {
		t.Errorf("a repository without a commit must use the target directory, got %q", got)
	}
}

// A directory without the marker is an interrupted clone. Reading a partial
// tree is worse than not reading it: "not found here" would be indist-
// inguishable from "not in the repository". With no reachable repository to
// re-clone from, the run falls back rather than trusting the debris.
func TestAcquireSourceScope_IgnoresAnUnmarkedDirectory(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(trustirfacts.SourceDir(runDir, testRepo, testCommit), 0o755); err != nil {
		t.Fatal(err)
	}
	fallback := "/fixtures/vulnerable"
	got, pinned := acquireSourceScope(context.Background(), nil, runDir,
		"file:///nonexistent-repository", testCommit, fallback)
	if pinned || got != fallback {
		t.Fatalf("root=%q pinned=%v, want the fallback when the checkout cannot be completed", got, pinned)
	}
}

// The real path: no checkout yet, so one is made. This is what moves the
// whole run onto the pinned revision instead of the target directory.
func TestAcquireSourceScope_ChecksOutWhenAbsent(t *testing.T) {
	origin := t.TempDir()
	gitInit(t, origin)
	commit := gitHead(t, origin)

	runDir := t.TempDir()
	got, pinned := acquireSourceScope(context.Background(), nil, runDir, origin, commit, "/fixtures/vulnerable")
	if !pinned {
		t.Fatalf("pinned = false; the checkout should have been made. root=%q", got)
	}
	if _, err := os.Stat(filepath.Join(got, "core", "crypto", "signed_hdr.c")); err != nil {
		t.Fatalf("the acquired tree must contain the repository's files: %v", err)
	}
	if !trustirfacts.SourceAvailable(runDir, origin, commit) {
		t.Error("the checkout must be marked complete so later stages reuse it")
	}
}

// gitInit makes a local repository holding the file this case is about, at
// the repository-relative path a ToolFact location would name.
func gitInit(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet")
	run("config", "user.email", "t@t.invalid")
	run("config", "user.name", "t")
	if err := os.MkdirAll(filepath.Join(dir, "core", "crypto"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "core", "crypto", "signed_hdr.c"),
		[]byte("int shdr_load_pub_key(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "--quiet", "-m", "init")
}

func gitHead(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// The manifest is what preprocess walks and what invariants, expert and
// verifier resolve citations against — none of them see the pipeline's own
// config. Leaving it at the target directory while the tools read the
// checkout restores the two-scope split, invisibly.
func TestRecordScannedRoot_ManifestNamesTheTreeActuallyRead(t *testing.T) {
	runDir := t.TempDir()
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "run-a",
		RepoURL:       testRepo,
		Commit:        testCommit,
		LocalPath:     "/fixtures/CVE-2026-44362/vulnerable",
	}); err != nil {
		t.Fatal(err)
	}

	const scanned = "/runs/run-a/02_tool_facts/trustir/src/df16a35b"
	if err := recordScannedRoot(runDir, scanned); err != nil {
		t.Fatalf("recordScannedRoot: %v", err)
	}

	got, err := runfs.LoadManifest(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if got.LocalPath != scanned {
		t.Fatalf("manifest local_path = %q, want the scanned tree %q", got.LocalPath, scanned)
	}
	// Identity must survive the rewrite: everything keyed on repository+commit
	// (the fact tables, the deterministic fact ids) resolves through it.
	if got.RepoURL != testRepo || got.Commit != testCommit || got.RunID != "run-a" {
		t.Errorf("rewriting local_path must not disturb the run's identity: %+v", got)
	}
}

// The source root must be absolute. It is derived from the run directory,
// which is relative by default ("runs/run-b"), and a tool that shells out
// does not resolve that the way an in-process reader does: across p11,
// run-a and run-b every one of ripgrep's 17 calls failed with "No such file
// or directory" while read_file in the same round succeeded, and nothing
// surfaced it — a failed action is recorded as an observation like any other.
func TestAcquireSourceScope_ReturnsAnAbsolutePath(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	rel, err := filepath.Rel(wd, runDir)
	if err != nil {
		t.Skipf("run dir is not expressible relative to cwd: %v", err)
	}
	markCheckout(t, rel, testRepo, testCommit)

	got, pinned := acquireSourceScope(context.Background(), nil, rel, testRepo, testCommit, "/fixtures/vulnerable")
	if !pinned {
		t.Fatal("the checkout is present; pinned must be true")
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("source root = %q, want an absolute path — a subprocess cannot resolve a relative one", got)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("the absolute root must exist: %v", err)
	}
}
