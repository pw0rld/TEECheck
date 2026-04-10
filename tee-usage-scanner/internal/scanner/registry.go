package scanner

import (
	"context"
	"fmt"
	"sort"
)

type GraphRegistry struct {
	adapters map[string]GraphAdapter
	order    []string
}

func NewGraphRegistry() *GraphRegistry {
	return &GraphRegistry{adapters: make(map[string]GraphAdapter)}
}

func (r *GraphRegistry) Register(a GraphAdapter) {
	name := a.Name()
	if _, exists := r.adapters[name]; !exists {
		r.order = append(r.order, name)
	}
	r.adapters[name] = a
}

func (r *GraphRegistry) Get(name string) (GraphAdapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

func (r *GraphRegistry) Available() []string {
	var names []string
	for _, name := range r.order {
		if r.adapters[name].Available() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (r *GraphRegistry) RunAll(ctx context.Context, req GraphRequest) (GraphResult, error) {
	var results []GraphResult
	for _, name := range r.order {
		a := r.adapters[name]
		if !a.Available() {
			continue
		}
		result, err := a.ExtractGraph(ctx, req)
		if err != nil {
			return GraphResult{}, fmt.Errorf("graph adapter %s: %w", name, err)
		}
		results = append(results, result)
	}
	return MergeGraphResults(results...), nil
}

func (r *GraphRegistry) RunByName(ctx context.Context, name string, req GraphRequest) (GraphResult, error) {
	a, ok := r.adapters[name]
	if !ok {
		return GraphResult{}, fmt.Errorf("unknown graph adapter: %s", name)
	}
	if !a.Available() {
		return GraphResult{}, fmt.Errorf("graph adapter %s is not available", name)
	}
	return a.ExtractGraph(ctx, req)
}
