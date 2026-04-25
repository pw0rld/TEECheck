package actions

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Registry dispatches ActionRequests to the registered Handler.
// It is safe for concurrent use after construction.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{handlers: map[string]Handler{}}
}

// NewDefaultRegistry returns a registry pre-populated with the M1
// built-in handlers: list_dir, read_file, ripgrep. Further handlers
// (tree_sitter_outline, reverse_trace, etc.) will be added in later
// milestones.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(ListDirHandler{})
	r.Register(ReadFileHandler{})
	r.Register(RipgrepHandler{})
	return r
}

// Register adds a handler to the registry. If a handler with the same
// name is already present it is overwritten.
func (r *Registry) Register(h Handler) {
	r.handlers[h.Name()] = h
}

// IsExecutorBacked reports whether the handler registered under
// name implements ExecutorBacked and returned true. The planner
// uses this to skip its manual tool_call_* event emission so the
// executor's events are not duplicated. Unknown names report false.
func (r *Registry) IsExecutorBacked(name string) bool {
	h, ok := r.handlers[name]
	if !ok {
		return false
	}
	eb, ok := h.(ExecutorBacked)
	if !ok {
		return false
	}
	return eb.IsExecutorBacked()
}

// Names returns the sorted list of registered handler names.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Run dispatches a single ActionRequest to its handler. Unknown actions
// are reported as OK=false with an "unknown action" error — they do not
// consume a round or propagate up as Go errors.
//
// Run stamps result.Name (in case the handler forgot) and records
// DurationMs.
func (r *Registry) Run(ctx context.Context, req ActionRequest) ActionResult {
	h, ok := r.handlers[req.Name]
	if !ok {
		return ActionResult{
			Name:  req.Name,
			OK:    false,
			Error: fmt.Sprintf("unknown action: %s", req.Name),
		}
	}
	start := time.Now()
	result := h.Run(ctx, req)
	if result.Name == "" {
		result.Name = req.Name
	}
	if result.DurationMs == 0 {
		result.DurationMs = time.Since(start).Milliseconds()
	}
	return result
}
