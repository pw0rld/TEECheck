package repofetch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FetchResult struct {
	LocalPath string
	Commit    string
	RepoURL   string
	Cloned    bool
}

func Fetch(target string) (FetchResult, error) {
	if IsURL(target) {
		return cloneRepo(target)
	}
	return fetchLocal(target)
}

func IsURL(s string) bool {
	return strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "git@")
}

func cloneRepo(url string) (FetchResult, error) {
	dir, err := os.MkdirTemp("", "teecheck-clone-*")
	if err != nil {
		return FetchResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	cmd := exec.Command("git", "clone", "--depth", "50", url, dir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return FetchResult{}, fmt.Errorf("git clone %s: %w", url, err)
	}
	commit, err := getHeadCommit(dir)
	if err != nil {
		os.RemoveAll(dir)
		return FetchResult{}, err
	}
	return FetchResult{LocalPath: dir, Commit: commit, RepoURL: url, Cloned: true}, nil
}

func fetchLocal(path string) (FetchResult, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return FetchResult{}, fmt.Errorf("resolve path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return FetchResult{}, fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return FetchResult{}, fmt.Errorf("%s is not a directory", abs)
	}
	commit, err := getHeadCommit(abs)
	if err != nil {
		commit = "unknown"
	}
	var repoURL string
	out, err := exec.Command("git", "-C", abs, "remote", "get-url", "origin").Output()
	if err == nil {
		repoURL = strings.TrimSpace(string(out))
	}
	return FetchResult{LocalPath: abs, Commit: commit, RepoURL: repoURL, Cloned: false}, nil
}

func getHeadCommit(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD in %s: %w", dir, err)
	}
	return strings.TrimSpace(string(out)), nil
}
