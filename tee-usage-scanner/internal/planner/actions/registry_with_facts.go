package actions

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"

// NewDefaultRegistryWithFacts extends NewDefaultRegistryWithSinks with the
// fact_layer_query action (§7.1, §24): the Planner's entry point into the
// structured CodeQL/TrustIR fact layer. eng is typically a *codeql.Engine
// in production and a fake satisfying trustirfacts.Engine in tests (see
// internal/trustirfacts's fakeEngine pattern, mirrored by this package's
// own tests — trustirfacts is not modified to expose it).
//
// eng may be nil (e.g. a caller running with --facts off, §12): the
// registered handler still answers other actions normally and only fails
// closed, per-call, when fact_layer_query itself is invoked.
func NewDefaultRegistryWithFacts(catalogPath string, eng trustirfacts.Engine, queryPackDir string) *Registry {
	r := NewDefaultRegistryWithSinks(catalogPath)
	r.Register(&FactLayerQueryHandler{Engine: eng, QueryPackDir: queryPackDir})
	return r
}
