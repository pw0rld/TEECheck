package trustirfacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// dbBuiltMarker is written into a database directory only after
// eng.CreateDatabase returns success. Its presence — not merely the
// directory existing — is what a cache hit means: a directory left behind
// by a crashed or killed build must be rebuilt, not treated as done.
const dbBuiltMarker = ".trustirfacts-db-built"

// srcClonedMarker plays the same role for the checkout: written only after
// the clone and checkout both succeed, so a tree left behind by an
// interrupted clone is never mistaken for the pinned revision. Handing a
// half-cloned tree to the planner would be worse than handing it nothing —
// "file not found" would then mean "not in this partial copy" while reading
// as "not in the repository".
const srcClonedMarker = ".trustirfacts-src-cloned"

// dbDirName names a database directory deterministically from repository
// and commit, so two Requests for the same repo+commit resolve to the same
// path — the mechanism behind "same commit's DB is built once" (§23.3's
// acceptance criterion). It does not need to be reversible, only stable and
// filesystem-safe.
func dbDirName(repository, commit string) string {
	sum := sha256.Sum256([]byte(normalizeRepo(repository) + "@" + commit))
	return hex.EncodeToString(sum[:])[:24]
}

// databaseDir is the explicit, visible run-directory path for one
// repository+commit's database (§23.3: "落到 run 目录作为显式 artifact，不是缓存副作用").
func databaseDir(runDir, repository, commit string) string {
	return filepath.Join(runfs.TrustIRToolFactsDir(runDir), "db", dbDirName(repository, commit))
}

// SourceDir is where this package checks out repository@commit to build the
// database from. It is a run artifact on the same footing as the database,
// under the same deterministic name.
//
// It used to be an os.MkdirTemp the build deleted on the way out. Only the
// database survived, and a database is queryable but not readable: the run
// held a full, pinned checkout of the exact revision under audit for the
// duration of one CodeQL invocation and then threw it away, while every
// source-reading tool in the same run was pointed at a benchmark fixture
// holding a single file. That is the split BUG-002 is about — the fact layer
// answering about core/kernel/ree_fs_ta.c while reverse_trace could not see
// the file existed.
//
// Callers outside this package use it to point their own tools at the same
// tree the facts came from; it returns a path whether or not anything is
// there yet, so check for existence (Available) before relying on it.
func SourceDir(runDir, repository, commit string) string {
	return filepath.Join(runfs.TrustIRToolFactsDir(runDir), "src", dbDirName(repository, commit))
}

// SourceAvailable reports whether SourceDir holds a completed checkout. The
// marker is written only after the clone succeeds, so a directory left by an
// interrupted clone reads as unavailable rather than as a usable tree.
func SourceAvailable(runDir, repository, commit string) bool {
	_, err := os.Stat(filepath.Join(SourceDir(runDir, repository, commit), srcClonedMarker))
	return err == nil
}

// EnsureSource acquires the run's source tree: repository@commit checked out
// under the run directory, reusing a completed checkout if one is there.
//
// It is exported because the checkout stopped being the fact layer's private
// scratch space. It is the tree the whole run reads — preprocess, the
// architecture and invariant models, the planner's actions and the scanner
// bus tool — so the pipeline acquires it once, before the first stage, and
// every stage resolves paths against the same revision. The fact layer's own
// database build calls the same function and finds the checkout already
// there.
//
// git clone --depth is deliberately absent here (see cloneAtRevision): a
// pinned CVE revision can be arbitrarily far behind the branch tip, which is
// why internal/repofetch's shallow clone cannot serve this purpose.
func EnsureSource(ctx context.Context, ex executor.Executor, runDir, repository, commit string) (string, error) {
	return ensureSource(ctx, ex, runDir, repository, commit)
}

// ensureSource checks out repository@commit under the run directory and
// returns the tree's path, reusing a completed checkout if one is there.
//
// A checkout that exists without its marker is the debris of an interrupted
// clone and is removed before cloning again; git itself refuses to clone
// into a non-empty directory, so leaving it would wedge every later run
// against the same run directory.
func ensureSource(ctx context.Context, ex executor.Executor, runDir, repository, commit string) (string, error) {
	tree := SourceDir(runDir, repository, commit)
	if SourceAvailable(runDir, repository, commit) {
		return tree, nil
	}
	if err := os.RemoveAll(tree); err != nil {
		return "", fmt.Errorf("clear incomplete checkout: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(tree), 0o755); err != nil {
		return "", fmt.Errorf("create source parent dir: %w", err)
	}
	if err := cloneAtRevision(ctx, ex, repository, commit, tree); err != nil {
		return "", fmt.Errorf("clone %s@%s: %w", repository, commit, err)
	}
	marker := filepath.Join(tree, srcClonedMarker)
	if err := os.WriteFile(marker, []byte(commit+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write src-cloned marker: %w", err)
	}
	return tree, nil
}

// ensureDatabase builds the CodeQL database for repository@commit if it is
// not already built, and reports whether an existing build was reused.
// Building means: check out the full repository tree at commit under the run
// directory (see ensureSource — the checkout is a kept artifact, so the rest
// of the run can read the same revision the facts describe), then
// CreateDatabase with BuildMode "none" (§23.3 — the only build mode the spike
// proved works for C without a project build system).
func ensureDatabase(ctx context.Context, eng Engine, ex executor.Executor, dbPath, runDir, repository, commit, extraPATH string) (reused bool, err error) {
	marker := filepath.Join(dbPath, dbBuiltMarker)
	if _, statErr := os.Stat(marker); statErr == nil {
		return true, nil
	}

	tree, err := ensureSource(ctx, ex, runDir, repository, commit)
	if err != nil {
		return false, err
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return false, fmt.Errorf("create db parent dir: %w", err)
	}
	if err := eng.CreateDatabase(ctx, codeql.CreateDBOptions{
		Language:   "cpp",
		SourceRoot: tree,
		DBPath:     dbPath,
		Overwrite:  true, // a stale partial dir (no marker) must not block a rebuild
		BuildMode:  "none",
		ExtraPATH:  extraPATH,
	}); err != nil {
		return false, fmt.Errorf("create database: %w", err)
	}

	if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return false, fmt.Errorf("write db-built marker: %w", err)
	}
	return false, nil
}
