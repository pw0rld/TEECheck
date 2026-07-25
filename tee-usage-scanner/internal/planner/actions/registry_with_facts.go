package actions

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"

// NewDefaultRegistryWithFacts extends NewDefaultRegistryWithNav with the
// fact_layer_query action: the Planner's entry point into the structured
// CodeQL/TrustIR fact layer. eng may be nil (facts off); the handler then
// fails closed per-call when fact_layer_query is invoked.
func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, queryPackDir string) *Registry {
	r := NewDefaultRegistryWithNav()
	r.Register(&FactLayerQueryHandler{Engine: eng, QueryPackDir: queryPackDir})
	return r
}
