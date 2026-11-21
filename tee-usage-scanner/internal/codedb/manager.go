// Package codedb owns the lifecycle of a run's CodeQL database and the
// pinned source checkout it is built from.
//
// It exists because two packages need the same database. internal/repoindex
// queries it for the whole-repo program index; internal/trustirfacts queries
// it for TWE facts. Before this package the resolution and build lived
// inside trustirfacts as unexported functions, so a second consumer could
// only have built a second database — 91 seconds and 322 MB, twice, for the
// same revision — or reimplemented the path derivation and drifted from it.
//
// By default the database and checkout are explicit run artifacts keyed on
// (repository, commit). An optional shared cache pins immutable source and
// database masters by exact commit and CodeQL version; each run records its
// source binding and receives a private database copy for writable analysis.
package codedb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// dbBuiltMarker is written into a database directory only after
// CreateDatabase returns success. Its presence — not merely the directory
// existing — is what a cache hit means: a directory left behind by a crashed
// or killed build must be rebuilt, not treated as done.
const dbBuiltMarker = ".trustirfacts-db-built"

// srcClonedMarker plays the same role for the checkout: written only after
// the clone and checkout both succeed, so a tree left behind by an
// interrupted clone is never mistaken for the pinned revision. Handing a
// half-cloned tree to the planner would be worse than handing it nothing —
// "file not found" would then mean "not in this partial copy" while reading
// as "not in the repository".
const srcClonedMarker = ".trustirfacts-src-cloned"

// State is what a consumer can learn about a database without building it.
const (
	StateAbsent = "absent"
	StateReady  = "ready"
)

// Scope identifies one database: a run directory and the revision the
// database is about.
type Scope struct {
	RunDir     string
	Repository string
	Commit     string
}

// DatabaseProvider is the seam every consumer takes.
//
// It is an interface rather than a concrete *Manager so a test can supply a
// prebuilt database without a CodeQL binary, and so a caller cannot
// accidentally construct a second manager: the pipeline builds one value and
// threads it to both repoindex and trustirfacts, which is what makes "one
// database per run" a property of the wiring rather than a coincidence.
type DatabaseProvider interface {
	// Ensure returns the database path, building it if it is not built yet.
	Ensure(ctx context.Context, scope Scope) (string, error)
	// Path returns where the database for this scope lives, whether or not
	// anything is there.
	Path(scope Scope) string
	// State says whether the database is already built. A consumer asks
	// before Ensure, because afterwards every state is ready: a fact derived
	// from a database this run did not build is a fact about whatever that
	// build saw, and that belongs in its coverage gaps.
	State(scope Scope) string
}

// Engine is the slice of the CodeQL engine this package needs. Analyze is
// deliberately absent: building a database and querying one are different
// jobs, and a package that owns the lifecycle should not be able to run
// queries as a side effect.
type Engine interface {
	Available() bool
	CreateDatabase(ctx context.Context, opts codeql.CreateDBOptions) error
}

// Manager builds and locates the run's database and source checkout.
type Manager struct {
	eng Engine
	ex  executor.Executor
	// extraPATH is prepended to PATH for the CodeQL subprocess. Normally
	// unnecessary; it exists for a future build mode that needs a compiler.
	extraPATH string
	cacheDir  string
}

func New(eng Engine, ex executor.Executor) *Manager {
	return &Manager{eng: eng, ex: ex}
}

// WithExtraPATH returns a copy that prepends dir to the CodeQL subprocess's
// PATH.
func (m *Manager) WithExtraPATH(dir string) *Manager {
	out := *m
	out.extraPATH = dir
	return &out
}

// WithCacheDir enables immutable shared source/DB masters. Every database
// handed to query engines is still a private run-local materialization.
func (m *Manager) WithCacheDir(dir string) *Manager {
	out := *m
	out.cacheDir = ""
	if strings.TrimSpace(dir) != "" {
		out.cacheDir = absolute(dir)
	}
	return &out
}

// NormalizeRepo collapses scheme, trailing slash, and ".git" suffix
// differences so "https://github.com/OP-TEE/optee_os",
// "https://github.com/OP-TEE/optee_os.git", and
// "git@github.com:OP-TEE/optee_os.git" all key the same identity.
//
// It lives here because this package derives directory names from it, and
// those names must not change: a different normalization is a different
// database path, so every existing run's database and checkout would be
// invisible and rebuilt. internal/trustirfacts calls it for its fact-table
// keys rather than keeping a second copy, so the two cannot drift.
func NormalizeRepo(repository string) string {
	s := strings.ToLower(strings.TrimSpace(repository))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "git@")
	s = strings.Replace(s, ":", "/", 1) // git@host:owner/repo -> host/owner/repo
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return s
}

// dirName names a directory deterministically from repository and commit, so
// two consumers of the same revision resolve to the same path — the
// mechanism behind "the same commit's database is built once" (§23.3). It
// does not need to be reversible, only stable and filesystem-safe.
func dirName(repository, commit string) string {
	sum := sha256.Sum256([]byte(NormalizeRepo(repository) + "@" + commit))
	return hex.EncodeToString(sum[:])[:24]
}

// Path is the explicit, visible run-directory location of one revision's
// database (§23.3: an artifact, not a cache side effect).
func (m *Manager) Path(scope Scope) string {
	return absolute(filepath.Join(runfs.TrustIRToolFactsDir(scope.RunDir), "db", dirName(scope.Repository, scope.Commit)))
}

// absolute resolves a path built from the run directory against this
// process's working directory.
//
// Every path this Manager produces is handed to a subprocess: git clone as a
// destination, git checkout as a working directory, codeql as a database
// argument. A relative run directory — "runs/recon-001", which is what
// --output-dir defaults to — means each of those resolves against whatever
// directory the subprocess happens to start in.
//
// Two of the three survived that by accident, because they run as children
// of this process and inherit its directory. The third did not: the executor
// refuses a relative working directory outright, so on the first real run
// against OP-TEE the clone succeeded and the checkout was rejected. The
// pinned revision was never checked out, the run silently fell back to the
// branch tip, and the program index degraded to no function cards at all.
// Making the paths absolute here fixes all three at once, rather than the
// one that happened to report it.
func absolute(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

// State reports whether the database is built. It reads the marker rather
// than the directory: a directory without one is the debris of an
// interrupted build.
func (m *Manager) State(scope Scope) string {
	if m.cacheDir != "" {
		var metadata databaseMetadata
		if err := readCacheJSON(m.bindingPath(scope, "database"), &metadata); err != nil || metadata.Schema != cacheSchema {
			return StateAbsent
		}
	}
	if _, err := os.Stat(filepath.Join(m.Path(scope), dbBuiltMarker)); err == nil {
		return StateReady
	}
	return StateAbsent
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
// holding a single file. That is the split this exists to prevent — the fact layer
// answering about core/kernel/ree_fs_ta.c while reverse_trace could not see
// the file existed.
//
// It returns a path whether or not anything is there yet, so check
// SourceAvailable before relying on it.
func (m *Manager) SourceDir(scope Scope) string {
	if m.cacheDir != "" {
		if binding, err := m.readSourceBinding(scope); err == nil {
			return binding.SourceRoot
		}
	}
	return absolute(filepath.Join(runfs.TrustIRToolFactsDir(scope.RunDir), "src", dirName(scope.Repository, scope.Commit)))
}

// SourceAvailable reports whether SourceDir holds a completed checkout. The
// marker is written only after the clone succeeds, so a directory left by an
// interrupted clone reads as unavailable rather than as a usable tree.
func (m *Manager) SourceAvailable(scope Scope) bool {
	if m.cacheDir != "" {
		_, err := m.validBoundSource(scope)
		return err == nil
	}
	_, err := os.Stat(filepath.Join(m.SourceDir(scope), srcClonedMarker))
	return err == nil
}

// ResolvedCommit reports the exact source commit pinned by EnsureSource.
// Callers using symbolic refs can record it in their run manifest. Changing
// Scope.Commit creates a new run binding, but reuses the same shared source.
func (m *Manager) ResolvedCommit(scope Scope) (string, error) {
	if m.cacheDir == "" {
		return scope.Commit, nil
	}
	b, err := m.readSourceBinding(scope)
	if err != nil {
		return "", err
	}
	return b.Commit, nil
}

// EnsureSource acquires the run's source tree: repository@commit checked out
// under the run directory, reusing a completed checkout if one is there.
//
// The checkout is not the fact layer's private scratch space. It is the tree
// the whole run reads — the program index, the planner's actions, the
// scanner bus tool — so the pipeline acquires it once, before the first
// stage, and every stage resolves paths against the same revision. The
// database build calls this same method and finds the checkout already
// there.
//
// A checkout that exists without its marker is the debris of an interrupted
// clone and is removed before cloning again; git itself refuses to clone
// into a non-empty directory, so leaving it would wedge every later run
// against the same run directory.
//
// git clone --depth is deliberately absent (see cloneAtRevision): a pinned
// CVE revision can be arbitrarily far behind the branch tip, which is why
// internal/repofetch's shallow clone cannot serve this purpose.
func (m *Manager) EnsureSource(ctx context.Context, scope Scope) (string, error) {
	if m.cacheDir != "" {
		return m.ensureSharedSource(ctx, scope)
	}
	tree := m.SourceDir(scope)
	if m.SourceAvailable(scope) {
		return tree, nil
	}
	if err := os.RemoveAll(tree); err != nil {
		return "", fmt.Errorf("clear incomplete checkout: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(tree), 0o755); err != nil {
		return "", fmt.Errorf("create source parent dir: %w", err)
	}
	if err := cloneAtRevision(ctx, m.ex, scope.Repository, scope.Commit, tree); err != nil {
		return "", fmt.Errorf("clone %s@%s: %w", scope.Repository, scope.Commit, err)
	}
	marker := filepath.Join(tree, srcClonedMarker)
	if err := os.WriteFile(marker, []byte(scope.Commit+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write src-cloned marker: %w", err)
	}
	return tree, nil
}

// Ensure builds the CodeQL database for this scope if it is not already
// built, and returns its path.
//
// Building means: check out the full repository tree at commit under the run
// directory (see EnsureSource — the checkout is a kept artifact, so the rest
// of the run can read the same revision the facts describe), then
// CreateDatabase with BuildMode "none" (§23.3 — the only build mode the
// spike proved works for C without a project build system).
func (m *Manager) Ensure(ctx context.Context, scope Scope) (string, error) {
	if m.cacheDir != "" {
		return m.ensureSharedDatabase(ctx, scope)
	}
	dbPath := m.Path(scope)
	if m.State(scope) == StateReady {
		return dbPath, nil
	}

	tree, err := m.EnsureSource(ctx, scope)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return "", fmt.Errorf("create db parent dir: %w", err)
	}
	if err = m.buildDatabase(ctx, tree, dbPath); err != nil {
		return "", err
	}
	return dbPath, nil
}

func (m *Manager) buildDatabase(ctx context.Context, tree, dbPath string) error {
	opts := codeql.CreateDBOptions{
		Language:   "cpp",
		SourceRoot: tree,
		DBPath:     dbPath,
		Overwrite:  true, // a stale partial dir (no marker) must not block a rebuild
		BuildMode:  "none",
		ExtraPATH:  m.extraPATH,
	}
	if err := m.eng.CreateDatabase(ctx, opts); err != nil {
		if ctx.Err() != nil || !isTransientBuildFailure(err) {
			return fmt.Errorf("create database: %w", err)
		}
		fmt.Fprintf(os.Stderr, "CodeQL database creation hit an internal JVM/TRAP failure; clearing partial database and retrying once with --threads=1: %v\n", err)
		if cleanupErr := os.RemoveAll(dbPath); cleanupErr != nil {
			return fmt.Errorf("clear partial database after transient failure (%v): %w", err, cleanupErr)
		}
		opts.Threads = 1
		opts.Overwrite = true
		if retryErr := m.eng.CreateDatabase(ctx, opts); retryErr != nil {
			return fmt.Errorf("create database recovery failed (initial error: %v): %w", err, retryErr)
		}
	}

	marker := filepath.Join(dbPath, dbBuiltMarker)
	if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write db-built marker: %w", err)
	}
	return nil
}

var internalExit100 = regexp.MustCompile(`\bexit status 100\b`)

// CodeQL uses exit 100 for internal errors. JVM/TRAP mmap markers and native
// JVM crash reports also occur in wrappers that omit the process exit code.
// Retrying is bounded to once; ordinary build, configuration and extractor
// errors are unchanged.
func isTransientBuildFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	message := strings.ToLower(err.Error())
	if internalExit100.MatchString(message) {
		return true
	}
	for _, marker := range []string{"internalerror", "mmappage", "diskwritablestringstore", "sigbus"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// These headers identify a JVM fatal-error report even when its wrapper
	// returns a generic exit status (for example exit 2 rather than exit 100).
	if strings.Contains(message, "problematic frame:") || strings.Contains(message, "hs_err") {
		return true
	}
	if strings.Contains(message, "sigsegv") || strings.Contains(message, "core dump will be written") {
		for _, marker := range []string{"java", "jvm", "openjdk", "hotspot", "stubroutines"} {
			if strings.Contains(message, marker) {
				return true
			}
		}
	}
	return false
}
