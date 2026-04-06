package tools

import "context"

type Adapter interface {
	SearchKeywords(ctx context.Context, repoRoot string, paths []string, keywords []string, limit int) ([]SearchHit, error)
}
