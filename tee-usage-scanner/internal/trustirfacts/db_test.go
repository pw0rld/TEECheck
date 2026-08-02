package trustirfacts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDbDirName_DeterministicAndDiscriminating(t *testing.T) {
	a := dbDirName("https://github.com/OP-TEE/optee_os", "abc123")
	b := dbDirName("https://github.com/OP-TEE/optee_os", "abc123")
	if a != b {
		t.Fatal("same repository+commit must name the same db dir")
	}
	if dbDirName("https://github.com/OP-TEE/optee_os", "def456") == a {
		t.Error("different commit must name a different db dir")
	}
	if dbDirName("https://github.com/other/repo", "abc123") == a {
		t.Error("different repository must name a different db dir")
	}
	// Repository URL variants that normalize the same must still name the
	// same db dir, so a build under one spelling is reused under another.
	if dbDirName("https://github.com/OP-TEE/optee_os.git", "abc123") != a {
		t.Error("equivalent repository spellings must name the same db dir")
	}
}

// TestEnsureDatabase_CacheHitSkipsBuild proves the §23.3 acceptance
// criterion directly against the cache-key logic, without a fake Engine at
// all: a pre-existing marker means ensureDatabase never calls out to build
// anything (no clone attempted, so this is genuinely offline).
func TestEnsureDatabase_CacheHitSkipsBuild(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "db")
	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbPath, dbBuiltMarker), []byte("stamp"), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := &fakeEngine{available: true}
	reused, err := ensureDatabase(context.Background(), eng, nil, dbPath, t.TempDir(), "this-repo-is-never-cloned", "commit", "")
	if err != nil {
		t.Fatalf("ensureDatabase: %v", err)
	}
	if !reused {
		t.Error("expected reused=true on a cache hit")
	}
	if eng.createDBCalls != 0 {
		t.Errorf("createDBCalls = %d, want 0 (cache hit must not rebuild)", eng.createDBCalls)
	}
}

// TestEnsureDatabase_MissBuildsOnceThenCaches builds against a real local
// git repository (offline) and a fake CodeQL engine, and proves that a
// second call for the same repository+commit does not rebuild.
func TestEnsureDatabase_MissBuildsOnceThenCaches(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")
	writeAndCommit(t, origin, "main.c", "int main(void) { return 0; }\n", "init")
	commit := headCommit(t, origin)

	runDir := t.TempDir()
	dbPath := filepath.Join(runDir, "db")
	eng := &fakeEngine{available: true}

	reused, err := ensureDatabase(context.Background(), eng, nil, dbPath, runDir, origin, commit, "")
	if err != nil {
		t.Fatalf("first ensureDatabase: %v", err)
	}
	if reused {
		t.Error("first call should be a cache miss (reused=false)")
	}
	if eng.createDBCalls != 1 {
		t.Fatalf("createDBCalls after first call = %d, want 1", eng.createDBCalls)
	}
	if _, err := os.Stat(filepath.Join(dbPath, dbBuiltMarker)); err != nil {
		t.Errorf("expected a built marker under dbPath after a successful build: %v", err)
	}

	reused, err = ensureDatabase(context.Background(), eng, nil, dbPath, runDir, origin, commit, "")
	if err != nil {
		t.Fatalf("second ensureDatabase: %v", err)
	}
	if !reused {
		t.Error("second call for the same repository+commit should be a cache hit")
	}
	if eng.createDBCalls != 1 {
		t.Errorf("createDBCalls after second call = %d, want still 1 (no rebuild)", eng.createDBCalls)
	}
}

// The checkout the database was built from must survive the build, at the
// path SourceDir names.
//
// It used to be an os.MkdirTemp deleted on the way out, so a run held a full
// pinned checkout of the revision under audit for the duration of one CodeQL
// invocation and then destroyed it — while every source-reading tool in the
// same run was pointed at a benchmark fixture containing one file. The fact
// layer would answer about core/kernel/ree_fs_ta.c and reverse_trace could
// not see that the file existed. See docs/bugs/BUG-002 §3.2.
func TestEnsureDatabase_KeepsTheCheckoutItBuiltFrom(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")
	// A nested path on purpose: a ToolFact location is repository-relative,
	// and resolving one against this tree is the whole point of keeping it.
	if err := os.MkdirAll(filepath.Join(origin, "core", "crypto"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeAndCommit(t, origin, "core/crypto/signed_hdr.c", "int shdr_load_pub_key(void) { return 0; }\n", "init")
	commit := headCommit(t, origin)

	runDir := t.TempDir()
	dbPath := filepath.Join(runDir, "db")

	if _, err := ensureDatabase(context.Background(), &fakeEngine{available: true},
		nil, dbPath, runDir, origin, commit, ""); err != nil {
		t.Fatalf("ensureDatabase: %v", err)
	}

	if !SourceAvailable(runDir, origin, commit) {
		t.Fatal("the checkout must be available after a successful build")
	}
	// And it must be the real tree, readable at the same relative paths the
	// facts report — that equivalence is what lets a tool resolve a
	// ToolFact location.
	body, err := os.ReadFile(filepath.Join(SourceDir(runDir, origin, commit), "core", "crypto", "signed_hdr.c"))
	if err != nil {
		t.Fatalf("the kept checkout must be readable at the fact's own relative path: %v", err)
	}
	if !strings.Contains(string(body), "shdr_load_pub_key") {
		t.Errorf("checkout content = %q, want the committed source", body)
	}
}

// A tree left behind by an interrupted clone must not be mistaken for the
// pinned revision: "file not found" in a half-copy reads exactly like "not
// in the repository", which is the inference BUG-002 is about.
func TestEnsureSource_IncompleteCheckoutIsRedone(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")
	writeAndCommit(t, origin, "main.c", "int main(void) { return 0; }\n", "init")
	commit := headCommit(t, origin)

	runDir := t.TempDir()
	tree := SourceDir(runDir, origin, commit)
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	// Debris: a file, but no marker.
	if err := os.WriteFile(filepath.Join(tree, "stale.c"), []byte("junk\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := ensureSource(context.Background(), nil, runDir, origin, commit); err != nil {
		t.Fatalf("ensureSource over debris: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree, "stale.c")); err == nil {
		t.Error("the incomplete checkout must be cleared, not cloned into")
	}
	if !SourceAvailable(runDir, origin, commit) {
		t.Error("after re-cloning the checkout must be marked available")
	}
}

// TestEnsureDatabase_CreateDatabaseFailureIsNotCached proves a failed build
// leaves no marker behind, so a later call retries rather than silently
// treating the failure as evidence of "no vulnerability" (§2 decision-8).
func TestEnsureDatabase_CreateDatabaseFailureIsNotCached(t *testing.T) {
	origin := t.TempDir()
	git(t, origin, "init", "--quiet")
	git(t, origin, "config", "user.email", "test@test.com")
	git(t, origin, "config", "user.name", "test")
	writeAndCommit(t, origin, "main.c", "int main(void) { return 0; }\n", "init")
	commit := headCommit(t, origin)

	runDir := t.TempDir()
	dbPath := filepath.Join(runDir, "db")
	eng := &fakeEngine{available: true, createDBErr: errBoom}

	_, err := ensureDatabase(context.Background(), eng, nil, dbPath, runDir, origin, commit, "")
	if err == nil {
		t.Fatal("expected an error when CreateDatabase fails")
	}
	if _, statErr := os.Stat(filepath.Join(dbPath, dbBuiltMarker)); statErr == nil {
		t.Error("a failed build must not leave a built marker behind")
	}
}
