package actions

// NewDefaultRegistryWithSinks returns a registry pre-populated with
// the M1 read-only actions (list_dir, read_file, ripgrep) plus the
// M2 actions (tree_sitter_outline, sink_catalog_lookup).
//
// The catalogPath argument is the on-disk location of the sink
// catalog JSON file (typically `knowledge/sinks/rust.json`). It is
// stored on the SinkCatalogLookupHandler instance and lazy-loaded on
// first use, so a missing or invalid file is reported as an action
// error rather than a constructor panic.
func NewDefaultRegistryWithSinks(catalogPath string) *Registry {
	r := NewDefaultRegistry()
	r.Register(TreeSitterOutlineHandler{})
	// SinkCatalogLookupHandler caches state, so we register a pointer
	// rather than a value receiver.
	r.Register(&SinkCatalogLookupHandler{CatalogPath: catalogPath})
	// DoneHandler is the terminal action the planner loop watches for.
	r.Register(DoneHandler{})
	return r
}
