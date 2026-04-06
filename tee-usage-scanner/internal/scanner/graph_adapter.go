package scanner

import "context"

type GraphNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Language string `json:"language"`
}

type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type GraphResult struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type GraphRequest struct {
	RepoRoot  string
	Languages []string
	Focus     string
}

type GraphAdapter interface {
	Name() string
	Available() bool
	ExtractGraph(ctx context.Context, req GraphRequest) (GraphResult, error)
}
