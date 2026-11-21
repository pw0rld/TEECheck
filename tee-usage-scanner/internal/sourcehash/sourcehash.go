// Package sourcehash fingerprints the bytes and names of a source tree.
package sourcehash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Tree hashes all source entries except version-control metadata.
func Tree(root string) (string, error) { return TreeExcluding(root, nil) }

// TreeExcluding additionally excludes exact subtrees, such as a run directory
// nested inside the scanned checkout. Exclusions must be absolute paths.
func TreeExcluding(root string, exclusions []string) (string, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	excluded := map[string]bool{}
	for _, p := range exclusions {
		p, err = filepath.Abs(p)
		if err != nil {
			return "", err
		}
		if p == root {
			return "", fmt.Errorf("source hash cannot exclude source root")
		}
		// Match the canonical walk path even if callers entered via a
		// symlinked checkout (for example /tmp on macOS).
		if resolved, resolveErr := filepath.EvalSymlinks(p); resolveErr == nil {
			p = resolved
		}
		if p == root {
			return "", fmt.Errorf("source hash cannot exclude source root")
		}
		excluded[filepath.Clean(p)] = true
	}
	var entries []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if excluded[path] || d.Name() == ".git" || d.Name() == ".hg" || d.Name() == ".svn" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		entries = append(entries, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(entries)
	h := sha256.New()
	for _, path := range entries {
		rel, _ := filepath.Rel(root, path)
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		kind, digest := "directory", ""
		switch {
		case info.Mode().IsRegular():
			kind = "file"
			digest, err = fileDigest(path)
		case info.Mode()&os.ModeSymlink != 0:
			kind = "symlink"
			target, readErr := os.Readlink(path)
			if readErr != nil {
				return "", readErr
			}
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				return "", fmt.Errorf("resolve source symlink %s: %w", rel, resolveErr)
			}
			if !within(root, resolved) {
				return "", fmt.Errorf("source symlink %s escapes source root", rel)
			}
			for excludedPath := range excluded {
				if within(excludedPath, resolved) {
					return "", fmt.Errorf("source symlink %s points into excluded run artifacts", rel)
				}
			}
			// Include the link spelling; the target contents are hashed at their own
			// location in this tree (and cannot point outside the tree).
			digest = target
		case info.IsDir():
		default:
			return "", fmt.Errorf("unsupported source entry %s (%s)", rel, info.Mode())
		}
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00", filepath.ToSlash(rel), kind, digest)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// File hashes a file's contents after checking that its resolved path stays
// within root. Paths may be absolute or relative to root.
func File(root, path string) (string, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, filepath.FromSlash(path))
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !within(root, path) {
		return "", fmt.Errorf("observed file escapes source root: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("observed path is not a regular file: %s", path)
	}
	return fileDigest(path)
}

// Files hashes each requested regular file; keys are normalized relative paths.
func Files(root string, paths []string) (map[string]string, error) {
	root, err := canonicalRoot(root)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(paths))
	for _, path := range paths {
		absolute := path
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(root, filepath.FromSlash(path))
		}
		absolute, err = filepath.Abs(absolute)
		if err != nil {
			return nil, err
		}
		if !within(root, absolute) {
			// An absolute observation can use a symlinked spelling of root.
			absolute, err = filepath.EvalSymlinks(absolute)
			if err != nil || !within(root, absolute) {
				return nil, fmt.Errorf("observed path escapes source root: %s", path)
			}
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, err
		}
		if !within(root, resolved) {
			return nil, fmt.Errorf("observed path escapes source root: %s", path)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			continue
		}
		digest, err := File(root, absolute)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(root, absolute)
		result[filepath.ToSlash(rel)] = digest
	}
	return result, nil
}

func canonicalRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("source root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(absolute)
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
