package tools

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SearchHit struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type RepoAdapter interface {
	SearchKeywords(paths []string, keywords []string, limit int) ([]SearchHit, error)
}

type LocalRepoAdapter struct {
	Root string
}

func NewLocalRepoAdapter(root string) *LocalRepoAdapter {
	return &LocalRepoAdapter{Root: root}
}

func (r *LocalRepoAdapter) SearchKeywords(paths []string, keywords []string, limit int) ([]SearchHit, error) {
	if limit <= 0 {
		limit = 20
	}
	var hits []SearchHit
	for _, rel := range uniq(paths) {
		if len(hits) >= limit {
			break
		}
		full := filepath.Join(r.Root, rel)
		file, err := os.Open(full)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			for _, keyword := range keywords {
				if keyword == "" {
					continue
				}
				if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
					hits = append(hits, SearchHit{
						Path: rel,
						Line: lineNo,
						Text: strings.TrimSpace(line),
					})
					break
				}
			}
			if len(hits) >= limit {
				break
			}
		}
		_ = file.Close()
	}
	return hits, nil
}

func FormatHits(hits []SearchHit) []string {
	out := make([]string, 0, len(hits))
	for _, hit := range hits {
		out = append(out, fmt.Sprintf("%s:%d %s", hit.Path, hit.Line, hit.Text))
	}
	return out
}

func uniq(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
