package actions

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
)

// NewDefaultRegistryWithFacts extends NewDefaultRegistryWithNav with the
// fact_layer_query action (the Planner's entry point into the structured
// CodeQL/TrustIR fact layer) and twe_playbook_detail (the on-demand detail
// tier of the TWE prior knowledge).
//
// eng, db and playbooks may each be nil (facts off, no database provider, a
// knowledge root with no playbook directory); the handlers then fail closed
// per call rather than at construction.
//
// db is a parameter rather than something the handler resolves for itself so
// the run has exactly one database manager. A handler that built its own
// would compile, run, and quietly produce a second 322 MB database of the
// same revision.
func NewDefaultRegistryWithFacts(eng trustirfacts.Engine, db codedb.DatabaseProvider, queryPackDir string, playbooks PlaybookDetailSource) *Registry {
	r := NewDefaultRegistryWithNav()
	r.Register(&FactLayerQueryHandler{Engine: eng, DB: db, QueryPackDir: queryPackDir})
	r.Register(&TWEPlaybookDetailHandler{Source: playbooks})
	return r
}
