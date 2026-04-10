package staticcheck

import (
	"context"
	"fmt"
	"sort"
)

type Registry struct {
	adapters map[string]Adapter
	order    []string
}

func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]Adapter)}
}

func (r *Registry) Register(a Adapter) {
	name := a.Name()
	if _, exists := r.adapters[name]; !exists {
		r.order = append(r.order, name)
	}
	r.adapters[name] = a
}

func (r *Registry) Get(name string) (Adapter, bool) {
	a, ok := r.adapters[name]
	return a, ok
}

func (r *Registry) Available() []string {
	var names []string
	for _, name := range r.order {
		if r.adapters[name].Available() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (r *Registry) RunAll(ctx context.Context, req CheckRequest) ([]CheckFinding, error) {
	var all []CheckFinding
	for _, name := range r.order {
		a := r.adapters[name]
		if !a.Available() {
			continue
		}
		findings, err := a.Run(ctx, req)
		if err != nil {
			return all, fmt.Errorf("adapter %s: %w", name, err)
		}
		all = append(all, findings...)
	}
	return all, nil
}

func (r *Registry) RunByName(ctx context.Context, name string, req CheckRequest) ([]CheckFinding, error) {
	a, ok := r.adapters[name]
	if !ok {
		return nil, fmt.Errorf("unknown adapter: %s", name)
	}
	if !a.Available() {
		return nil, fmt.Errorf("adapter %s is not available", name)
	}
	return a.Run(ctx, req)
}
