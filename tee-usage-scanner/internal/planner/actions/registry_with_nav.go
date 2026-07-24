package actions

// NewDefaultRegistryWithNav returns the base read-only actions
// (list_dir, read_file, ripgrep) plus the language-agnostic navigation
// actions: tree_sitter_outline, reverse_trace, and the terminal done.
// The sink catalog is intentionally absent — guidance comes from the
// injected TWE/invariant/architecture prior knowledge, not a symbol list.
func NewDefaultRegistryWithNav() *Registry {
	r := NewDefaultRegistry()
	r.Register(TreeSitterOutlineHandler{})
	r.Register(ReverseTraceHandler{})
	r.Register(DoneHandler{})
	return r
}
