package scanner_test

import (
	"context"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/scanner"
)

type fakeGraphAdapter struct {
	name      string
	available bool
	result    scanner.GraphResult
}

func (f *fakeGraphAdapter) Name() string      { return f.name }
func (f *fakeGraphAdapter) Available() bool    { return f.available }
func (f *fakeGraphAdapter) ExtractGraph(_ context.Context, _ scanner.GraphRequest) (scanner.GraphResult, error) {
	return f.result, nil
}

func TestGraphRegistryRunAllMerges(t *testing.T) {
	reg := scanner.NewGraphRegistry()
	reg.Register(&fakeGraphAdapter{
		name: "tool-a", available: true,
		result: scanner.GraphResult{
			Nodes: []scanner.GraphNode{
				{ID: "file-main", Kind: "file", Name: "main.rs", Path: "src/main.rs", Language: "rust"},
				{ID: "sym-foo", Kind: "function", Name: "foo", Path: "src/main.rs", Language: "rust"},
			},
			Edges: []scanner.GraphEdge{
				{Source: "file-main", Target: "sym-foo", Kind: "defines"},
			},
		},
	})
	reg.Register(&fakeGraphAdapter{
		name: "tool-b", available: true,
		result: scanner.GraphResult{
			Nodes: []scanner.GraphNode{
				{ID: "file-main", Kind: "file", Name: "main.rs", Path: "src/main.rs", Language: "rust"},
				{ID: "sym-bar", Kind: "function", Name: "bar", Path: "src/lib.rs", Language: "rust"},
			},
			Edges: []scanner.GraphEdge{
				{Source: "sym-foo", Target: "sym-bar", Kind: "calls"},
			},
		},
	})
	reg.Register(&fakeGraphAdapter{name: "tool-c", available: false})

	result, err := reg.RunAll(context.Background(), scanner.GraphRequest{RepoRoot: "/tmp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(result.Nodes))
	}
	if len(result.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(result.Edges))
	}
}

func TestGraphRegistryAvailable(t *testing.T) {
	reg := scanner.NewGraphRegistry()
	reg.Register(&fakeGraphAdapter{name: "yes", available: true})
	reg.Register(&fakeGraphAdapter{name: "no", available: false})

	avail := reg.Available()
	if len(avail) != 1 || avail[0] != "yes" {
		t.Fatalf("expected [yes], got %v", avail)
	}
}

func TestMergeGraphResults(t *testing.T) {
	a := scanner.GraphResult{
		Nodes: []scanner.GraphNode{{ID: "n1", Kind: "file", Name: "a"}, {ID: "n2", Kind: "function", Name: "b"}},
		Edges: []scanner.GraphEdge{{Source: "n1", Target: "n2", Kind: "defines"}},
	}
	b := scanner.GraphResult{
		Nodes: []scanner.GraphNode{{ID: "n1", Kind: "file", Name: "a"}, {ID: "n3", Kind: "function", Name: "c"}},
		Edges: []scanner.GraphEdge{{Source: "n1", Target: "n2", Kind: "defines"}, {Source: "n2", Target: "n3", Kind: "calls"}},
	}
	merged := scanner.MergeGraphResults(a, b)
	if len(merged.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(merged.Nodes))
	}
	if len(merged.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(merged.Edges))
	}
}
