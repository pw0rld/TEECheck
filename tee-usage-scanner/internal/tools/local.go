package tools

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
)

type LocalAdapter struct{}

func NewLocalAdapter() *LocalAdapter {
	return &LocalAdapter{}
}

func (a *LocalAdapter) SearchKeywords(ctx context.Context, repoRoot string, paths []string, keywords []string, limit int) ([]SearchHit, error) {
	if limit <= 0 {
		limit = 8
	}
	keywords = uniqFold(keywords)
	targets := paths
	if len(targets) == 0 {
		targets = []string{"."}
	}
	var hits []SearchHit
	for _, rel := range targets {
		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}
		full := filepath.Join(repoRoot, rel)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.IsDir() {
			err = filepath.Walk(full, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || len(hits) >= limit {
					return nil
				}
				fileHits, _ := searchFile(path, repoRoot, keywords, limit-len(hits))
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
