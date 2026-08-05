package runfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// .git holds thousands of objects. Counting them would swamp any real
// difference between two checkouts and make the hash track the packfile
// layout instead of the code.
func TestBuildScope_ExcludesVCSDirectories(t *testing.T) {
	root := tree(t, map[string]string{
		"core/crypto/signed_hdr.c": "int f(void) { return 0; }",
		"core/kernel/ree_fs_ta.c":  "int g(void) { return 0; }",
		".git/COMMIT_EDITMSG":      "wip",
		".git/objects/ab/cdef":     "binary-ish",
	})
	got := BuildScope("https://example/repo", "abc123", root)
	if got.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2 — .git must not be counted", got.FileCount)
	}
	if got.Hash == "" {
		t.Error("BuildScope produced no hash")
	}
}

// The root lives under the run directory, so two runs of the same revision
// have different roots. A hash that included the root would make every
// cross-run comparison fail and the check worthless.
func TestScopeHash_IgnoresRoot(t *testing.T) {
	a := artifacts.ScannedScope{RepoURL: "r", Commit: "c", Root: "/runs/run-a/src", FileCount: 3291}
	b := artifacts.ScannedScope{RepoURL: "r", Commit: "c", Root: "/runs/run-b/src", FileCount: 3291}
	if ScopeHash(a) != ScopeHash(b) {
		t.Errorf("same revision, same file count, different run dir must hash alike: %s vs %s",
			ScopeHash(a), ScopeHash(b))
	}
}

// The case the hash exists for: a stage reading a four-file fixture while
// another reads the full checkout of the same revision.
func TestScopeHash_DistinguishesDifferentTreeSizes(t *testing.T) {
	full := artifacts.ScannedScope{RepoURL: "r", Commit: "c", FileCount: 3291}
	fixture := artifacts.ScannedScope{RepoURL: "r", Commit: "c", FileCount: 4}
	if ScopeHash(full) == ScopeHash(fixture) {
		t.Error("a 3291-file checkout and a 4-file fixture must not share a scope hash")
	}
}

func writeManifest(t *testing.T, runDir string, m artifacts.Manifest) {
	t.Helper()
	if err := WriteJSON(ManifestPath(runDir), m); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyScope_AcceptsTheRecordedTree(t *testing.T) {
	root := tree(t, map[string]string{"a.c": "x", "b.c": "y"})
	runDir := t.TempDir()
	writeManifest(t, runDir, artifacts.Manifest{
		RunID: "run-1", RepoURL: "r", Commit: "c", LocalPath: root,
		Scope: BuildScope("r", "c", root),
	})
	if err := VerifyScope(runDir, root); err != nil {
		t.Errorf("the recorded tree must verify: %v", err)
	}
}

// The scope split in one test: the fact layer analysed the full checkout while
// reverse_trace read the fixture, and nothing anywhere said so.
func TestVerifyScope_RejectsADifferentTree(t *testing.T) {
	full := tree(t, map[string]string{"a.c": "x", "b.c": "y", "c.c": "z"})
	fixture := tree(t, map[string]string{"a.c": "x"})
	runDir := t.TempDir()
	writeManifest(t, runDir, artifacts.Manifest{
		RunID: "run-1", RepoURL: "r", Commit: "c", LocalPath: full,
		Scope: BuildScope("r", "c", full),
	})

	err := VerifyScope(runDir, fixture)
	if err == nil {
		t.Fatal("a stage reading a smaller tree must be rejected")
	}
	for _, want := range []string{"scope mismatch", "3 files", "1 files"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must state both sizes, missing %q: %v", want, err)
		}
	}
}

// Runs predating the field exist. Refusing to read them would make this a
// migration break rather than a guard.
func TestVerifyScope_ToleratesAManifestWithoutScope(t *testing.T) {
	root := tree(t, map[string]string{"a.c": "x"})
	runDir := t.TempDir()
	writeManifest(t, runDir, artifacts.Manifest{RunID: "run-1", LocalPath: root})
	if err := VerifyScope(runDir, root); err != nil {
		t.Errorf("a manifest with no scope must verify, got: %v", err)
	}
}

func TestPhase0PathsStayUnderRunDir(t *testing.T) {
	runDir := filepath.Join("tmp", "runs", "run-1")
	wants := map[string]string{
		RepoFactsPath(runDir):     filepath.Join(runDir, "01_context", "repo_facts.v1.json"),
		ProjectMapPath(runDir):    filepath.Join(runDir, "01_context", "project_map.v1.json"),
		EvidenceSlicesDir(runDir): filepath.Join(runDir, "04_planner", "evidence_slices"),
	}
	for got, want := range wants {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}
