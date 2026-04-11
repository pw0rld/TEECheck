package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolvePath normalizes a repo-relative path and guarantees:
//
//  1. The path does not escape repoRoot (no absolute paths, no leading/embedded "..").
//  2. No ancestor directory between repoRoot and the resolved target is a symbolic link.
//  3. If the final target itself exists, it is not a symbolic link.
//
// It does NOT require the target to exist — non-existent paths are allowed
// through so that actions like ripgrep can pass include patterns that do
// not correspond to real files. Callers handle not-found errors themselves.
//
// The returned path is an absolute path rooted at repoRoot.
func ResolvePath(repoRoot, rel string) (string, error) {
	if rel == "" {
		rel = "."
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths not allowed: %s", rel)
	}
	cleaned := filepath.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repo root: %s", rel)
	}

	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", fmt.Errorf("resolve repo root: %w", err)
	}
	full := filepath.Join(absRoot, cleaned)
	if !strings.HasPrefix(full+string(filepath.Separator), absRoot+string(filepath.Separator)) && full != absRoot {
		return "", fmt.Errorf("path escapes repo root: %s", rel)
	}

	// Walk every ancestor component from absRoot down to full and reject
	// any that is a symlink. Non-existent components are allowed — we
	// stop walking at the first missing one.
	if cleaned != "." {
		current := absRoot
		parts := strings.Split(cleaned, string(filepath.Separator))
		for _, part := range parts {
			if part == "" || part == "." {
				continue
			}
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil {
				if os.IsNotExist(err) {
					break
				}
				return "", fmt.Errorf("lstat %s: %w", current, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("symlink not allowed: %s", part)
			}
		}
	}

	return full, nil
}
