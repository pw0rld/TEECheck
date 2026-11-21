package codedb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/executor"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

const cacheSchema = 1

type sourceBinding struct {
	Schema         int    `json:"schema"`
	RepositoryHash string `json:"repository_hash"`
	RequestHash    string `json:"request_hash,omitempty"`
	Commit         string `json:"commit"`
	SourceRoot     string `json:"source_root"`
	TreeHash       string `json:"tree_content_hash"`
}

func (m *Manager) bindingPath(scope Scope, kind string) string {
	return absolute(filepath.Join(runfs.TrustIRToolFactsDir(scope.RunDir), "cache", kind+"-"+dirName(scope.Repository, scope.Commit)+".json"))
}

// The request key pins a symbolic ref once for this run, but not across runs.
func sourceRequestHash(scope Scope) (string, error) {
	repo, err := cacheRepository(scope.Repository)
	if err != nil {
		return "", err
	}
	return cacheHash(repositoryIdentity(repo) + "\x00" + scope.Commit), nil
}

func (m *Manager) readSourceBinding(scope Scope) (sourceBinding, error) {
	var b sourceBinding
	if err := readCacheJSON(m.bindingPath(scope, "source"), &b); err != nil {
		return b, err
	}
	request, err := sourceRequestHash(scope)
	if err != nil {
		return b, err
	}
	repository, repoErr := cacheRepository(scope.Repository)
	if repoErr != nil {
		return b, repoErr
	}
	if b.Schema != cacheSchema || b.RequestHash != request || !fullCommit.MatchString(b.Commit) || b.RepositoryHash != cacheHash(repositoryIdentity(repository)) || !sha256Hex.MatchString(b.TreeHash) {
		return b, fmt.Errorf("source cache binding does not match requested scope")
	}
	expected := filepath.Join(m.cacheDir, "sources", b.RepositoryHash, b.Commit, "src")
	if b.SourceRoot != expected {
		return b, fmt.Errorf("source cache binding has unexpected source root")
	}
	return b, nil
}

func (m *Manager) validBoundSource(scope Scope) (sourceBinding, error) {
	b, err := m.readSourceBinding(scope)
	if err != nil {
		return b, err
	}
	return b, validateSource(b)
}

func validateSource(b sourceBinding) error {
	var published sourceBinding
	if err := readCacheJSON(filepath.Join(filepath.Dir(b.SourceRoot), "source.json"), &published); err != nil {
		return fmt.Errorf("read completed source cache: %w", err)
	}
	if published.Schema != cacheSchema || published.Commit != b.Commit || published.RepositoryHash != b.RepositoryHash || published.SourceRoot != b.SourceRoot || published.TreeHash != b.TreeHash {
		return fmt.Errorf("source cache metadata mismatch")
	}
	marker, err := os.ReadFile(filepath.Join(b.SourceRoot, srcClonedMarker))
	if err != nil || strings.TrimSpace(string(marker)) != b.Commit {
		return fmt.Errorf("source cache missing exact-commit completion marker")
	}
	digest, err := sourcehash.Tree(b.SourceRoot)
	if err != nil {
		return fmt.Errorf("source cache content: %w", err)
	}
	if digest != b.TreeHash {
		return fmt.Errorf("source cache content changed; refusing corrupted cached checkout")
	}
	return nil
}

func (m *Manager) ensureSharedSource(ctx context.Context, scope Scope) (string, error) {
	request, err := sourceRequestHash(scope)
	if err != nil {
		return "", err
	}
	unlock, err := lockCache(ctx, m.bindingPath(scope, "source")+".lock")
	if err != nil {
		return "", err
	}
	defer unlock()
	if b, err := m.readSourceBinding(scope); err == nil {
		if err = validateSource(b); err != nil {
			return "", err
		}
		if err = m.bindSource(scope, b); err != nil {
			return "", err
		}
		return b.SourceRoot, ctx.Err()
	} else if !os.IsNotExist(err) {
		return "", err
	}
	repository, err := cacheRepository(scope.Repository)
	if err != nil {
		return "", err
	}
	repoHash := cacheHash(repositoryIdentity(repository))
	unlockRepo, err := lockCache(ctx, filepath.Join(m.cacheDir, "locks", "repo-"+repoHash+".lock"))
	if err != nil {
		return "", err
	}
	defer unlockRepo()
	mirror, commit, err := m.resolveCachedRevision(ctx, repository, scope.Commit, repoHash)
	if err != nil {
		return "", err
	}
	entry := filepath.Join(m.cacheDir, "sources", repoHash, commit)
	b := sourceBinding{Schema: cacheSchema, RepositoryHash: repoHash, RequestHash: request, Commit: commit, SourceRoot: filepath.Join(entry, "src")}
	if err = readCacheJSON(filepath.Join(entry, "source.json"), &b); err == nil {
		// Published entries are immutable. Corruption is never silently replaced
		// underneath another run already reading the same absolute source path.
		if b.SourceRoot != filepath.Join(entry, "src") || b.Commit != commit || b.RepositoryHash != repoHash {
			return "", fmt.Errorf("source cache metadata mismatch")
		}
		if err = validateSource(b); err != nil {
			return "", err
		}
	} else if os.IsNotExist(err) {
		if err = removeCacheTree(entry); err != nil {
			return "", err
		}
		if err = os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
			return "", err
		}
		tmp, err := os.MkdirTemp(filepath.Dir(entry), ".source-*")
		if err != nil {
			return "", err
		}
		defer removeCacheTree(tmp)
		tree := filepath.Join(tmp, "src")
		if err = cloneAtRevision(ctx, m.ex, mirror, commit, tree); err != nil {
			return "", fmt.Errorf("materialize cached source: %w", err)
		}
		if err = os.RemoveAll(filepath.Join(tree, ".git")); err != nil {
			return "", err
		}
		if err = os.WriteFile(filepath.Join(tree, srcClonedMarker), []byte(commit+"\n"), 0o644); err != nil {
			return "", err
		}
		b.TreeHash, err = sourcehash.Tree(tree)
		if err != nil {
			return "", err
		}
		if err = writeCacheJSON(filepath.Join(tmp, "source.json"), b); err != nil {
			return "", err
		}
		if err = freezeTree(tree); err != nil {
			return "", err
		}
		if err = ctx.Err(); err != nil {
			return "", err
		}
		if err = os.Rename(tmp, entry); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("read source cache metadata: %w", err)
	}
	b.RequestHash = request
	if err = m.bindSource(scope, b); err != nil {
		return "", err
	}
	return b.SourceRoot, nil
}

// Keep the exact-SHA alias alongside the original ref, so the pipeline can
// pin its manifest before constructing downstream scopes without resolving
// a moving ref for a second time.
func (m *Manager) bindSource(scope Scope, b sourceBinding) error {
	b.RequestHash, _ = sourceRequestHash(scope)
	if err := writeCacheJSON(m.bindingPath(scope, "source"), b); err != nil {
		return err
	}
	if scope.Commit != b.Commit {
		scope.Commit = b.Commit
		b.RequestHash, _ = sourceRequestHash(scope)
		return writeCacheJSON(m.bindingPath(scope, "source"), b)
	}
	return nil
}

var fullCommit = regexp.MustCompile(`^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$`)
var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (m *Manager) resolveCachedRevision(ctx context.Context, repository, revision, repoHash string) (string, string, error) {
	if err := assertSafeGitArg("revision", revision); err != nil {
		return "", "", err
	}
	mirror := filepath.Join(m.cacheDir, "mirrors", repoHash+".git")
	if _, err := os.Stat(filepath.Join(mirror, "HEAD")); os.IsNotExist(err) {
		if err = os.MkdirAll(filepath.Dir(mirror), 0o755); err != nil {
			return "", "", err
		}
		tmp, err := os.MkdirTemp(filepath.Dir(mirror), ".mirror-*")
		if err != nil {
			return "", "", err
		}
		defer os.RemoveAll(tmp)
		if _, err = m.cacheGit(ctx, "git-cache-clone", "", true, "clone", "--mirror", "--quiet", "--", repository, tmp); err != nil {
			return "", "", err
		}
		if err = removeCacheTree(mirror); err != nil {
			return "", "", err
		}
		if err = os.Rename(tmp, mirror); err != nil {
			return "", "", err
		}
	} else if err != nil {
		return "", "", err
	}
	resolve := func() (string, error) {
		out, err := m.cacheGit(ctx, "git-cache-resolve", mirror, false, "rev-parse", "--verify", revision+"^{commit}")
		commit := strings.TrimSpace(out)
		if err == nil && !fullCommit.MatchString(commit) {
			err = fmt.Errorf("git did not return an exact commit")
		}
		return strings.ToLower(commit), err
	}
	// A pinned full object already present is offline-reusable. Symbolic and
	// abbreviated refs refresh first so a new run cannot inherit an old tip.
	if fullCommit.MatchString(revision) {
		if commit, err := resolve(); err == nil {
			return mirror, commit, nil
		}
	}
	if _, err := m.cacheGit(ctx, "git-cache-fetch", mirror, true, "-c", "gc.auto=0", "fetch", "--quiet", "--prune", "origin"); err != nil {
		return "", "", err
	}
	commit, err := resolve()
	return mirror, commit, err
}

func (m *Manager) cacheGit(ctx context.Context, name, dir string, network bool, args ...string) (string, error) {
	policy := executor.NetworkNone
	if network {
		policy = executor.NetworkAllow
	}
	r := executor.OrLocal(m.ex).Run(ctx, executor.Request{Name: name, Command: "git", Args: args, WorkDir: dir, Profile: executor.Profile{Network: policy, Write: executor.WriteWorkspace, Timeout: cloneTimeout, EnvAllowlist: executor.InheritedEnvNames()}})
	if err := r.Err(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, tail(r.Combined(), 2000))
	}
	return string(r.Stdout), nil
}

// Keep credentials out of directory keys, metadata and git remote config.
// Authentication belongs in a git credential helper or SSH configuration.
func cacheRepository(repository string) (string, error) {
	repository = strings.TrimSpace(repository)
	if err := assertSafeGitArg("repository", repository); err != nil {
		return "", err
	}
	if strings.HasPrefix(strings.ToLower(repository), "ext::") {
		return "", fmt.Errorf("shared cache refuses ext:: git transport")
	}
	if strings.Contains(repository, "://") {
		u, err := url.Parse(repository)
		if err != nil {
			return "", fmt.Errorf("invalid repository URL")
		}
		if u.User != nil && u.User.Username() != "git" {
			return "", fmt.Errorf("shared cache requires credential-free repository URL; use a git credential helper")
		}
		if u.User != nil {
			if _, set := u.User.Password(); set {
				return "", fmt.Errorf("shared cache requires credential-free repository URL; use a git credential helper")
			}
		}
		u.Host = strings.ToLower(u.Host)
		u.RawQuery = ""
		u.Fragment = ""
		if u.Scheme == "file" {
			return filepath.Clean(u.Path), nil
		}
		return u.String(), nil
	}
	if strings.Contains(repository, ":") && !filepath.IsAbs(repository) {
		return repository, nil
	}
	p := absolute(repository)
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return p, nil
}

func repositoryIdentity(repository string) string {
	if filepath.IsAbs(repository) {
		return repository
	}
	// Transport spelling and optional .git suffix should not fragment a
	// remote identity. Preserve local path case on case-sensitive filesystems.
	return NormalizeRepo(repository)
}

func readCacheJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode cache metadata: %w", err)
	}
	return nil
}
