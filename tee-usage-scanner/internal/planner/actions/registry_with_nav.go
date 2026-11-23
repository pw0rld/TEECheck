package actions

// NewDefaultRegistryWithNav returns the base read-only actions
// (list_dir, read_file, ripgrep) plus the language-agnostic navigation
// actions: tree_sitter_outline, reverse_trace, 3-hop boundary closures,
// struct-field producer/consumer bridges, and the terminal done.
func NewDefaultRegistryWithNav() *Registry {
	r := NewDefaultRegistry()
	r.Register(GetRepositoryCardHandler{})
	r.Register(ListModulesHandler{})
	r.Register(ListFunctionsHandler{})
	r.Register(ListEntrySurfacesHandler{})
	r.Register(ListBoundaryClosuresHandler{})
	r.Register(GetStructFlowsHandler{})
	r.Register(FindSymbolsHandler{})
	r.Register(GetFunctionCardHandler{})
	r.Register(GetCallersHandler{})
	r.Register(TreeSitterOutlineHandler{})
	r.Register(ReverseTraceHandler{})
	r.Register(DoneHandler{})
	return r
}
