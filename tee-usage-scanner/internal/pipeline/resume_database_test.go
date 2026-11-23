package pipeline

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type resumedDatabaseFreezer struct {
	state string
	calls int
	scope codedb.Scope
	err   error
}

func (f *resumedDatabaseFreezer) FreezeFailedScope(scope codedb.Scope, err error) {
	f.calls++
	f.scope, f.err = scope, err
}

func (f *resumedDatabaseFreezer) State(codedb.Scope) string { return f.state }

func resumeDatabaseFixture(t *testing.T) (string, artifacts.Manifest, artifacts.RepoFacts) {
	t.Helper()
	runDir, repoRoot := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(repoRoot, "source.c"), []byte("int f(void) { return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := artifacts.Manifest{RunID: "resume-db", RepoURL: "https://example.invalid/repo", Commit: "abcdef1234567", LocalPath: repoRoot}
	m.Scope = runfs.BuildScope(m.RepoURL, m.Commit, repoRoot)
	facts := artifacts.RepoFacts{SchemaVersion: artifacts.SchemaVersionRepoFactsV1, RunID: m.RunID, Scope: m.Scope}
	return runDir, m, facts
}

func TestRestoreFailedDatabaseRetainsOriginalFailureRegardlessOfCurrentDBState(t *testing.T) {
	for _, currentState := range []string{codedb.StateAbsent, codedb.StateReady} {
		t.Run(currentState, func(t *testing.T) {
			runDir, manifest, facts := resumeDatabaseFixture(t)
			facts.IndexNote = "codeql database: create database: exit status 2"
			path := runfs.RepoFactsPath(runDir)
			if err := runfs.WriteJSON(path, facts); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			freezer := &resumedDatabaseFreezer{state: currentState}
			if err := restoreFailedDatabase(runDir, manifest, freezer); err != nil {
				t.Fatal(err)
			}
			want := codedb.Scope{RunDir: runDir, Repository: manifest.RepoURL, Commit: manifest.Commit}
			if freezer.calls != 1 || freezer.scope != want || freezer.err == nil || freezer.err.Error() != facts.IndexNote {
				t.Fatalf("failure was not restored: calls=%d scope=%+v error=%v", freezer.calls, freezer.scope, freezer.err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("restoring database failure modified the original index: %v", err)
			}
		})
	}
}

func TestRestoreFailedDatabaseDoesNotFreezeOtherIndexOutcomes(t *testing.T) {
	for _, note := range []string{
		"",
		"Symbols.ql: exit status 2",
		"symbol query returned no indexed definitions; source coverage is partial",
		"no pinned repository@commit; the program index needs one to build a database",
		"FieldAccesses.ql: codeql database: query failed",
	} {
		t.Run(note, func(t *testing.T) {
			runDir, manifest, facts := resumeDatabaseFixture(t)
			facts.IndexNote = note
			if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
				t.Fatal(err)
			}
			freezer := &resumedDatabaseFreezer{}
			if err := restoreFailedDatabase(runDir, manifest, freezer); err != nil || freezer.calls != 0 {
				t.Fatalf("unrelated index outcome was frozen: calls=%d err=%v", freezer.calls, err)
			}
		})
	}
}

func TestRestoreFailedDatabaseRejectsMissingCorruptOrMismatchedContext(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*artifacts.RepoFacts)
	}{
		{"missing schema", func(f *artifacts.RepoFacts) { f.SchemaVersion = "" }},
		{"wrong schema", func(f *artifacts.RepoFacts) { f.SchemaVersion = "other" }},
		{"missing run", func(f *artifacts.RepoFacts) { f.RunID = "" }},
		{"different run", func(f *artifacts.RepoFacts) { f.RunID = "other" }},
		{"missing scope", func(f *artifacts.RepoFacts) { f.Scope = artifacts.ScannedScope{} }},
		{"different repository", func(f *artifacts.RepoFacts) { f.Scope.RepoURL = "https://example.invalid/other" }},
		{"different commit", func(f *artifacts.RepoFacts) { f.Scope.Commit = "other" }},
		{"different root", func(f *artifacts.RepoFacts) { f.Scope.Root += "-other" }},
		{"different hash", func(f *artifacts.RepoFacts) { f.Scope.Hash = "other" }},
		{"different file count", func(f *artifacts.RepoFacts) { f.Scope.FileCount++ }},
		{"failure without reason", func(f *artifacts.RepoFacts) { f.IndexNote = "codeql database: " }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runDir, manifest, facts := resumeDatabaseFixture(t)
			tc.mutate(&facts)
			if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
				t.Fatal(err)
			}
			freezer := &resumedDatabaseFreezer{}
			if err := restoreFailedDatabase(runDir, manifest, freezer); err == nil || !strings.Contains(err.Error(), "resume database context") || freezer.calls != 0 {
				t.Fatalf("invalid context accepted: calls=%d err=%v", freezer.calls, err)
			}
		})
	}
	for _, content := range []string{"missing", "{", "null", "{}"} {
		t.Run(content, func(t *testing.T) {
			runDir, manifest, _ := resumeDatabaseFixture(t)
			if content != "missing" {
				path := runfs.RepoFactsPath(runDir)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			freezer := &resumedDatabaseFreezer{}
			if err := restoreFailedDatabase(runDir, manifest, freezer); err == nil || freezer.calls != 0 {
				t.Fatalf("missing/corrupt context accepted: calls=%d err=%v", freezer.calls, err)
			}
		})
	}
}

func TestRestoreFailedDatabaseRequiresManagerForRecordedFailure(t *testing.T) {
	runDir, manifest, facts := resumeDatabaseFixture(t)
	facts.IndexNote = "codeql database: original extraction failed"
	if err := runfs.WriteJSON(runfs.RepoFactsPath(runDir), facts); err != nil {
		t.Fatal(err)
	}
	if err := restoreFailedDatabase(runDir, manifest, nil); err == nil || !strings.Contains(err.Error(), "database manager is unavailable") {
		t.Fatalf("nil manager accepted for recorded failure: %v", err)
	}
}
