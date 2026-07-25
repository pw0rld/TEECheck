package actions

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"

// NewDefaultRegistryWithFacts extends NewDefaultRegistryWithNav with the
// fact_layer_query action (the Planner's entry point into the structured
// CodeQL/TrustIR fact layer) and twe_playbook_detail (the on-demand detail
// tier of the TWE prior knowledge).
//
// eng may be nil (facts off) and playbooks may be nil (a knowledge root with
// no playbook directory); both handlers then fail closed per call rather than
// at construction.
func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, queryPackDir string, playbooks PlaybookDetailSource) *Registry {
	r := NewDefaultRegistryWithNav()
	r.Register(&FactLayerQueryHandler{Engine: eng, QueryPackDir: queryPackDir})
	r.Register(&TWEPlaybookDetailHandler{Source: playbooks})
	return r
}
