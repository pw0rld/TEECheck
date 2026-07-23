package trustirfacts

import (
	"context"
	"os"
	"path/filepath"
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
	reused, err := ensureDatabase(context.Background(), eng, dbPath, "this-repo-is-never-cloned", "commit", "")
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

	dbPath := filepath.Join(t.TempDir(), "db")
	eng := &fakeEngine{available: true}

	reused, err := ensureDatabase(context.Background(), eng, dbPath, origin, commit, "")
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

	reused, err = ensureDatabase(context.Background(), eng, dbPath, origin, commit, "")
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

	dbPath := filepath.Join(t.TempDir(), "db")
	eng := &fakeEngine{available: true, createDBErr: errBoom}

	_, err := ensureDatabase(context.Background(), eng, dbPath, origin, commit, "")
	if err == nil {
		t.Fatal("expected an error when CreateDatabase fails")
	}
	if _, statErr := os.Stat(filepath.Join(dbPath, dbBuiltMarker)); statErr == nil {
		t.Error("a failed build must not leave a built marker behind")
	}
}
