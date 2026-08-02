package runfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// scopeSkipDirs are directories that hold no auditable source. They are
// excluded from the file count so the count describes the code, not the
// checkout's bookkeeping: .git alone contributes thousands of objects and
// would swamp any real difference between two trees.
var scopeSkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
}

// BuildScope walks root once and returns the scope record for it.
//
// The walk is the only cost, and it is the same walk any consumer would have
// to do to answer "how much code is here". A root that cannot be walked
// yields a scope with the identity fields set and FileCount zero rather than
// an error: a run against an unreadable tree should fail in the stage that
// needs the files, with that stage's own message, not here.
func BuildScope(repoURL, commit, root string) artifacts.ScannedScope {
	scope := artifacts.ScannedScope{RepoURL: repoURL, Commit: commit, Root: root}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if scopeSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		scope.FileCount++
		return nil
	})
	scope.Hash = ScopeHash(scope)
	return scope
}

// ScopeHash is the identity two stages compare. It deliberately excludes
// Root — see ScannedScope's doc comment.
func ScopeHash(s artifacts.ScannedScope) string {
	sum := sha256.Sum256([]byte(s.RepoURL + "\x00" + s.Commit + "\x00" + strconv.Itoa(s.FileCount)))
	return hex.EncodeToString(sum[:])[:16]
}

// VerifyScope reports whether root is the tree the manifest says the run is
// about.
//
// It is meant to be called by a stage that resolved a root of its own, so a
// disagreement surfaces as that stage's error instead of as a conclusion
// about the code. A manifest with no recorded scope is not an error: runs
// predating the field exist, and refusing to read them would make this check
// a migration break rather than a guard.
func VerifyScope(runDir, root string) error {
	manifest, err := LoadManifest(runDir)
	if err != nil {
		return fmt.Errorf("verify scope: %w", err)
	}
	if manifest.Scope.Hash == "" {
		return nil
	}
	got := BuildScope(manifest.Scope.RepoURL, manifest.Scope.Commit, root)
	if got.Hash == manifest.Scope.Hash {
		return nil
	}
	return fmt.Errorf(
		"scope mismatch: the run is recorded against %s@%s with %d files (%s), "+
			"but %s holds %d files (%s) — two stages reading different trees "+
			"produce evidence that cannot be reconciled",
		orUnset(manifest.Scope.RepoURL), orUnset(manifest.Scope.Commit),
		manifest.Scope.FileCount, manifest.Scope.Hash,
		root, got.FileCount, got.Hash)
}

func orUnset(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

// RepoFactsPath is the deterministic program index built from the pinned
// checkout: symbols, call edges, types and fields, and the edges the
// extractor could not resolve.
func RepoFactsPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "repo_facts.v1.json")
}

// ProjectMapPath is the neutral navigation view the planner browses:
// repository card, module cards, and references to the function card pages.
func ProjectMapPath(runDir string) string {
	return filepath.Join(ContextDir(runDir), "project_map.v1.json")
}

// EvidenceSlicesDir holds the per-lead expansions the planner retrieved. It
// lives under the planner's own directory rather than 01_context because the
// slices are a product of the investigation, not of project understanding.
func EvidenceSlicesDir(runDir string) string {
	return filepath.Join(runDir, "04_planner", "evidence_slices")
}
