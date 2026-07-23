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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// dbBuiltMarker is written into a database directory only after
// eng.CreateDatabase returns success. Its presence — not merely the
// directory existing — is what a cache hit means: a directory left behind
// by a crashed or killed build must be rebuilt, not treated as done.
const dbBuiltMarker = ".trustirfacts-db-built"

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

// ensureDatabase builds the CodeQL database for repository@commit if it is
// not already built, and reports whether an existing build was reused.
// Building means: clone the full repository tree at commit into a scratch
// directory (never reused across calls — only the resulting database is a
// persistent artifact), then CreateDatabase with BuildMode "none" (§23.3 —
// the only build mode the spike proved works for C without a project build
// system).
func ensureDatabase(ctx context.Context, eng Engine, dbPath, repository, commit, extraPATH string) (reused bool, err error) {
	marker := filepath.Join(dbPath, dbBuiltMarker)
	if _, statErr := os.Stat(marker); statErr == nil {
		return true, nil
	}

	work, err := os.MkdirTemp("", "trustirfacts-src-*")
	if err != nil {
		return false, fmt.Errorf("create scratch source dir: %w", err)
	}
	defer os.RemoveAll(work)

	tree := filepath.Join(work, "tree")
	if err := cloneAtRevision(ctx, repository, commit, tree); err != nil {
		return false, fmt.Errorf("clone %s@%s: %w", repository, commit, err)
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
