package scanner

import (
	"context"
	"fmt"
)

// ScanRequest carries the parameters for a graph scan.
type ScanRequest struct {
	RepoRoot  string
	Languages []string
	Focus     string
	Mode      string
}

// Scan runs all available graph adapters in the provided registry and returns
// a merged GraphResult. reg must not be nil; use scanner/all.NewDefaultGraphRegistry
// to obtain a registry pre-loaded with all built-in adapters.
func Scan(ctx context.Context, reg *GraphRegistry, req ScanRequest) (GraphResult, error) {
	if reg == nil {
		return GraphResult{}, fmt.Errorf("scan: registry is nil; use scanner/all.NewDefaultGraphRegistry()")
	}

	graphReq := GraphRequest{
		RepoRoot:  req.RepoRoot,
		Languages: req.Languages,
		Focus:     req.Focus,
	}

	result, err := reg.RunAll(ctx, graphReq)
	if err != nil {
		return GraphResult{}, fmt.Errorf("scan: %w", err)
	}
	fmt.Printf("Graph scan complete: %d nodes, %d edges (tools: %v)\n",
		len(result.Nodes), len(result.Edges), reg.Available())
	return result, nil
}
