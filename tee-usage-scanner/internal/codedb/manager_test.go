package codedb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDbDirName_DeterministicAndDiscriminating(t *testing.T) {
	a := dirName("https://github.com/OP-TEE/optee_os", "abc123")
	b := dirName("https://github.com/OP-TEE/optee_os", "abc123")
	if a != b {
		t.Fatal("same repository+commit must name the same db dir")
	}
	if dirName("https://github.com/OP-TEE/optee_os", "def456") == a {
		t.Error("different commit must name a different db dir")
	}
	if dirName("https://github.com/other/repo", "abc123") == a {
		t.Error("different repository must name a different db dir")
	}
	// Repository URL variants that normalize the same must still name the
	// same db dir, so a build under one spelling is reused under another.
	if dirName("https://github.com/OP-TEE/optee_os.git", "abc123") != a {
		t.Error("equivalent repository spellings must name the same db dir")
	}
}

// TestEnsureDatabase_CacheHitSkipsBuild proves the §23.3 acceptance
// criterion directly against the cache-key logic, without a fake Engine at
// all: a pre-existing marker means ensureDatabase never calls out to build
// anything (no clone attempted, so this is genuinely offline).
func TestEnsureDatabase_CacheHitSkipsBuild(t *testing.T) {
	m0 := New(nil, nil)
	scope := Scope{RunDir: t.TempDir(), Repository: "this-repo-is-never-cloned", Commit: "commit"}
	dbPath := m0.Path(scope)
	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbPath, dbBuiltMarker), []byte("stamp"), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := &fakeEngine{available: true}
	m := New(eng, nil)
	if m.State(scope) != StateReady {
		t.Error("a directory with a built marker must read as ready")
	}
	if _, err := m.Ensure(context.Background(), scope); err != nil {
		t.Fatalf("Ensure: %v", err)
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
	eng := &fakeEngine{available: true}
	m := New(eng, nil)
	scope := Scope{RunDir: runDir, Repository: origin, Commit: commit}

	if m.State(scope) != StateAbsent {
		t.Error("first call should be a cache miss")
	}
	dbPath, err := m.Ensure(context.Background(), scope)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if eng.createDBCalls != 1 {
		t.Fatalf("createDBCalls after first call = %d, want 1", eng.createDBCalls)
	}
	if _, err := os.Stat(filepath.Join(dbPath, dbBuiltMarker)); err != nil {
		t.Errorf("expected a built marker under dbPath after a successful build: %v", err)
	}

	if m.State(scope) != StateReady {
		t.Error("second call for the same repository+commit should be a cache hit")
	}
	if _, err := m.Ensure(context.Background(), scope); err != nil {
		t.Fatalf("second Ensure: %v", err)
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
	m := New(&fakeEngine{available: true}, nil)
	scope := Scope{RunDir: runDir, Repository: origin, Commit: commit}

	if _, err := m.Ensure(context.Background(), scope); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if !m.SourceAvailable(scope) {
		t.Fatal("the checkout must be available after a successful build")
	}
	// And it must be the real tree, readable at the same relative paths the
	// facts report — that equivalence is what lets a tool resolve a
	// ToolFact location.
	body, err := os.ReadFile(filepath.Join(m.SourceDir(scope), "core", "crypto", "signed_hdr.c"))
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
	m := New(nil, nil)
	scope := Scope{RunDir: runDir, Repository: origin, Commit: commit}
	tree := m.SourceDir(scope)
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	// Debris: a file, but no marker.
	if err := os.WriteFile(filepath.Join(tree, "stale.c"), []byte("junk\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := m.EnsureSource(context.Background(), scope); err != nil {
		t.Fatalf("EnsureSource over debris: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree, "stale.c")); err == nil {
		t.Error("the incomplete checkout must be cleared, not cloned into")
	}
	if !m.SourceAvailable(scope) {
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
	eng := &fakeEngine{available: true, createDBErr: errBoom}
	m := New(eng, nil)
	scope := Scope{RunDir: runDir, Repository: origin, Commit: commit}
	dbPath := m.Path(scope)

	_, err := m.Ensure(context.Background(), scope)
	if err == nil {
		t.Fatal("expected an error when CreateDatabase fails")
	}
	if _, statErr := os.Stat(filepath.Join(dbPath, dbBuiltMarker)); statErr == nil {
		t.Error("a failed build must not leave a built marker behind")
	}
}

// The three forms of one repository must key one database. A run that named
// its target with a trailing .git and a run that did not would otherwise
// each build their own 322 MB copy of the same revision.
func TestNormalizeRepo_CollapsesTheFormsThatNameOneRepository(t *testing.T) {
	want := NormalizeRepo("https://github.com/OP-TEE/optee_os")
	for _, form := range []string{
		"https://github.com/OP-TEE/optee_os.git",
		"http://github.com/OP-TEE/optee_os",
		"git@github.com:OP-TEE/optee_os.git",
		"https://github.com/OP-TEE/optee_os/",
		"  https://github.com/OP-TEE/OPTEE_OS  ",
	} {
		if got := NormalizeRepo(form); got != want {
			t.Errorf("NormalizeRepo(%q) = %q, want %q", form, got, want)
		}
	}
}

// The derived directory name is on disk in every existing run. Changing the
// normalization changes the name, which does not fail — it silently orphans
// every database and checkout already built, and the next run rebuilds from
// scratch while the old ones sit unreferenced. This pins the mapping.
func TestDirName_IsStableAcrossChanges(t *testing.T) {
	const (
		repo   = "https://github.com/OP-TEE/optee_os"
		commit = "a9386bf987d95374a6f7f4c7bcf850115e0e1a4e"
		// The name runs/run-b's database and checkout are stored under.
		want = "df16a35bfd62a0e59aec9b4e"
	)
	if got := dirName(repo, commit); got != want {
		t.Errorf("dirName(%s@%s) = %q, want %q — changing this orphans every database already on disk",
			repo, commit[:12], got, want)
	}
}

// A database directory without its marker is the debris of a crashed or
// killed build. Reading the directory instead of the marker would report it
// ready, and the run would query a half-extracted database — every "not
// found" from which is a statement about a partial index, not about the
// code.
func TestState_UnmarkedDirectoryIsNotReady(t *testing.T) {
	m := New(nil, nil)
	scope := Scope{RunDir: t.TempDir(), Repository: "r", Commit: "c"}
	if err := os.MkdirAll(m.Path(scope), 0o755); err != nil {
		t.Fatal(err)
	}
	// Debris a killed extractor would leave: real files, no marker.
	if err := os.WriteFile(filepath.Join(m.Path(scope), "db-cpp"), []byte("partial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m.State(scope) != StateAbsent {
		t.Error("a database directory with no built marker must read as absent, not ready")
	}
}
