package codedb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
)

type cacheEngine struct {
	mu      sync.Mutex
	version string
	builds  int
	fail    bool
	entered chan struct{}
	release chan struct{}
}

func (e *cacheEngine) Available() bool { return true }
func (e *cacheEngine) Version(context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.version, nil
}
func (e *cacheEngine) CreateDatabase(ctx context.Context, o codeql.CreateDBOptions) error {
	e.mu.Lock()
	e.builds++
	fail := e.fail
	entered, release := e.entered, e.release
	e.mu.Unlock()
	if err := os.MkdirAll(o.DBPath, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.DBPath, "dataset"), []byte("immutable facts\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.DBPath, "source-prefix"), []byte(o.SourceRoot), 0o644); err != nil {
		return err
	}
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
		}
	}
	if fail {
		return fmt.Errorf("ordinary extraction failure")
	}
	return nil
}
func (e *cacheEngine) count() int { e.mu.Lock(); defer e.mu.Unlock(); return e.builds }
func newSharedCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() { _ = removeCacheTree(dir) })
	return dir
}
func cacheScope(t *testing.T, repo, commit string) Scope {
	t.Helper()
	return Scope{RunDir: t.TempDir(), Repository: repo, Commit: commit}
}

func TestSharedCacheReusesBuildAndIsolatesQueries(t *testing.T) {
	repo, commit := newOrigin(t)
	cache := newSharedCache(t)
	eng := &cacheEngine{version: "2.24.0"}
	manager := New(eng, nil).WithCacheDir(cache)
	one := cacheScope(t, repo, commit)
	first, err := manager.Ensure(context.Background(), one)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(first, "dataset"), []byte("query wrote cache"), 0o644); err != nil {
		t.Fatal(err)
	}
	two := cacheScope(t, repo, commit)
	second, err := manager.Ensure(context.Background(), two)
	if err != nil {
		t.Fatal(err)
	}
	if eng.count() != 1 {
		t.Fatalf("builds=%d, want 1", eng.count())
	}
	if first == second {
		t.Fatal("queries were handed the same database")
	}
	data, err := os.ReadFile(filepath.Join(second, "dataset"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "immutable facts\n" {
		t.Fatalf("shared database was mutated: %s", data)
	}
	if manager.SourceDir(one) != manager.SourceDir(two) {
		t.Fatal("immutable source was not shared")
	}
	prefix, _ := os.ReadFile(filepath.Join(second, "source-prefix"))
	if string(prefix) != manager.SourceDir(two) {
		t.Fatalf("source prefix changed: %s", prefix)
	}
	info, _ := os.Stat(filepath.Join(manager.SourceDir(two), "version.txt"))
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatal("cached source is writable")
	}
	if _, err = os.Stat(filepath.Join(manager.SourceDir(two), ".git")); !os.IsNotExist(err) {
		t.Fatal("shared source retained writable Git metadata")
	}
}

func TestSharedCacheVersionAndExactRefIdentity(t *testing.T) {
	repo, _ := newOrigin(t)
	manager := New(&cacheEngine{version: "2.24.0"}, nil).WithCacheDir(newSharedCache(t))
	eng := manager.eng.(*cacheEngine)
	one := cacheScope(t, repo, "HEAD")
	if _, err := manager.Ensure(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	commit, err := manager.ResolvedCommit(one)
	if err != nil {
		t.Fatal(err)
	}
	alias := one
	alias.Commit = commit
	if manager.SourceDir(alias) != manager.SourceDir(one) || !manager.SourceAvailable(alias) {
		t.Fatal("exact-commit alias missing")
	}
	oldSource := manager.SourceDir(one)
	writeAndCommit(t, repo, "version.txt", "v3\n", "move HEAD")
	if _, err = manager.EnsureSource(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	pinned, _ := manager.ResolvedCommit(one)
	if pinned != commit {
		t.Fatal("symbolic ref drifted inside one run")
	}
	two := cacheScope(t, repo, "HEAD")
	if _, err = manager.Ensure(context.Background(), two); err != nil {
		t.Fatal(err)
	}
	newCommit, _ := manager.ResolvedCommit(two)
	if newCommit == commit || manager.SourceDir(two) == oldSource {
		t.Fatal("new run reused stale symbolic ref")
	}
	eng.mu.Lock()
	eng.version = "2.25.0"
	eng.mu.Unlock()
	if _, err = manager.Ensure(context.Background(), two); err != nil {
		t.Fatal(err)
	}
	if eng.count() != 3 {
		t.Fatalf("expected builds for two revisions and second version, got %d", eng.count())
	}
}

func TestSharedCachePinnedSourceDoesNotRefetch(t *testing.T) {
	repo, commit := newOrigin(t)
	manager := New(&cacheEngine{version: "2.24.0"}, nil).WithCacheDir(newSharedCache(t))
	if _, err := manager.EnsureSource(context.Background(), cacheScope(t, repo, commit)); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.EnsureSource(context.Background(), cacheScope(t, repo, commit)); err != nil {
		t.Fatalf("pinned hit fetched origin: %v", err)
	}
}

func TestSharedCacheConcurrentRunsBuildOnce(t *testing.T) {
	repo, commit := newOrigin(t)
	eng := &cacheEngine{version: "2.24.0", entered: make(chan struct{}, 1), release: make(chan struct{})}
	manager := New(eng, nil).WithCacheDir(newSharedCache(t))
	one, two := cacheScope(t, repo, commit), cacheScope(t, repo, commit)
	errs := make(chan error, 2)
	go func() { _, err := manager.Ensure(context.Background(), one); errs <- err }()
	select {
	case <-eng.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("build did not start")
	}
	go func() { _, err := manager.Ensure(context.Background(), two); errs <- err }()
	close(eng.release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if eng.count() != 1 {
		t.Fatalf("concurrent builds=%d", eng.count())
	}
}

func TestSharedCacheFailureDoesNotPublishPartialBuild(t *testing.T) {
	repo, commit := newOrigin(t)
	eng := &cacheEngine{version: "2.24.0", fail: true}
	manager := New(eng, nil).WithCacheDir(newSharedCache(t))
	one := cacheScope(t, repo, commit)
	if _, err := manager.Ensure(context.Background(), one); err == nil {
		t.Fatal("expected build failure")
	}
	if manager.State(one) == StateReady {
		t.Fatal("failed database marked ready")
	}
	eng.mu.Lock()
	eng.fail = false
	eng.mu.Unlock()
	if _, err := manager.Ensure(context.Background(), cacheScope(t, repo, commit)); err != nil {
		t.Fatal(err)
	}
	if eng.count() != 2 {
		t.Fatalf("partial build was reused; builds=%d", eng.count())
	}
}

func TestSharedCacheCancelledBuildCanBeRetried(t *testing.T) {
	repo, commit := newOrigin(t)
	eng := &cacheEngine{version: "2.24.0", entered: make(chan struct{}, 1), release: make(chan struct{})}
	manager := New(eng, nil).WithCacheDir(newSharedCache(t))
	one := cacheScope(t, repo, commit)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := manager.Ensure(ctx, one); result <- err }()
	select {
	case <-eng.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("build did not start")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled build: %v", err)
	}
	if manager.State(one) == StateReady {
		t.Fatal("cancelled build marked ready")
	}
	eng.mu.Lock()
	eng.release = nil
	eng.mu.Unlock()
	if _, err := manager.Ensure(context.Background(), cacheScope(t, repo, commit)); err != nil {
		t.Fatal(err)
	}
	if eng.count() != 2 {
		t.Fatalf("cancelled database reused; builds=%d", eng.count())
	}
}

func TestSharedCacheRejectsCorruption(t *testing.T) {
	for _, kind := range []string{"source", "database"} {
		t.Run(kind, func(t *testing.T) {
			repo, commit := newOrigin(t)
			eng := &cacheEngine{version: "2.24.0"}
			manager := New(eng, nil).WithCacheDir(newSharedCache(t))
			one := cacheScope(t, repo, commit)
			if _, err := manager.Ensure(context.Background(), one); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(manager.SourceDir(one), "version.txt")
			if kind == "database" {
				var metadata databaseMetadata
				if err := readCacheJSON(manager.bindingPath(one, "database"), &metadata); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(manager.cacheDir, "databases", metadata.Key, "db", "dataset")
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("corrupted"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Ensure(context.Background(), cacheScope(t, repo, commit)); err == nil || !strings.Contains(err.Error(), "content changed") {
				t.Fatalf("corruption accepted: %v", err)
			}
			if eng.count() != 1 {
				t.Fatal("corrupt published entry silently replaced")
			}
		})
	}
}

func TestSharedCacheLockIsCancellable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry.lock")
	unlock, err := lockCache(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err = lockCache(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait: %v", err)
	}
}

func TestSharedCacheRejectsCredentialsAndUnsafeSource(t *testing.T) {
	for _, repo := range []string{"https://name:secret@example.com/org/repo.git", "ext::sh command", "-repository"} {
		if _, err := cacheRepository(repo); err == nil {
			t.Fatalf("accepted unsafe repository: %s", repo)
		}
	}
	repo, commit := newOrigin(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(repo, "escape")); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "escape")
	git(t, repo, "commit", "-qm", "symlink")
	commit = headCommit(t, repo)
	manager := New(&cacheEngine{version: "2.24.0"}, nil).WithCacheDir(newSharedCache(t))
	if _, err := manager.EnsureSource(context.Background(), cacheScope(t, repo, commit)); err == nil || !strings.Contains(err.Error(), "escapes source root") {
		t.Fatalf("unsafe source accepted: %v", err)
	}
}
