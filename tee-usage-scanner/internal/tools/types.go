package tools

import "context"

type SearchHit struct {
	Path string
	Line int
	Text string
}

type Adapter interface {
	SearchKeywords(ctx context.Context, repoRoot string, paths []string, keywords []string, limit int) ([]SearchHit, error)
}
