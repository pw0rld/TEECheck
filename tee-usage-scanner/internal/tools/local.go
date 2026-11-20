package tools

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type LocalAdapter struct{}

func NewLocalAdapter() *LocalAdapter {
	return &LocalAdapter{}
}

func (a *LocalAdapter) SearchKeywords(ctx context.Context, repoRoot string, paths []string, keywords []string, limit int) ([]SearchHit, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	repoRoot = root
	if limit <= 0 {
		limit = 8
	}
	keywords = uniqFold(keywords)
	targets := paths
	if len(targets) == 0 {
		targets = []string{"."}
	}
	// Validate every explicit target before returning any source content.
	var resolved []string
	for _, target := range targets {
		full, err := searchTarget(root, target)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, full)
	}
	var hits []SearchHit
	for _, full := range resolved {
		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.IsDir() {
			err = filepath.Walk(full, func(path string, info os.FileInfo, err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil || info.IsDir() || len(hits) >= limit {
					return nil
				}
				resolvedPath, resolveErr := searchTarget(root, path)
				if resolveErr != nil {
					return nil // Ignore directory entries that link outside the repository.
				}
				fileHits, _ := searchFile(resolvedPath, repoRoot, keywords, limit-len(hits))
				hits = append(hits, fileHits...)
				return nil
			})
			if err != nil {
				return hits, err
			}
			continue
		}
		fileHits, err := searchFile(full, repoRoot, keywords, limit-len(hits))
		if err != nil {
			continue
		}
		hits = append(hits, fileHits...)
		if len(hits) >= limit {
			break
		}
	}
	return hits, nil
}

// searchTarget checks the resolved path, so a lexically in-root symlink cannot
// make this source-reading tool disclose a file outside its repository.
func searchTarget(root, target string) (string, error) {
	full := target
	if !filepath.IsAbs(full) {
		full = filepath.Join(root, full)
	}
	lexical := full
	full, err := filepath.EvalSymlinks(full)
	if err != nil {
		if rel, relErr := filepath.Rel(root, lexical); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("search target escapes repository: %q", target)
		}
		return "", err
	}
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("search target escapes repository: %q", target)
	}
	return full, nil
}

func searchFile(fullPath, repoRoot string, keywords []string, limit int) ([]SearchHit, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hits []SearchHit
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() && len(hits) < limit {
		lineNum++
		line := scanner.Text()
		lower := strings.ToLower(line)
		for _, keyword := range keywords {
			if keyword != "" && strings.Contains(lower, keyword) {
				rel, err := filepath.Rel(repoRoot, fullPath)
				if err != nil {
					rel = fullPath
				}
				hits = append(hits, SearchHit{
					Path: filepath.ToSlash(rel),
					Line: lineNum,
					Text: strings.TrimSpace(line),
				})
				break
			}
		}
	}
	return hits, scanner.Err()
}

func uniqFold(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
