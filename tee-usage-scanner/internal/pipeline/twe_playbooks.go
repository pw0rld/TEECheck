package pipeline

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/twecontext"
)

// buildTWEPlaybookSummaries converts a loaded TWE playbook catalog into the
// map planner.RunConfig.TWEPlaybooks expects, keyed by TWE id. This
// conversion lives in internal/pipeline (not internal/planner) so the
// planner package keeps its deliberate non-dependency on internal/twecontext
// — see planner.TWEPlaybookSummary's doc comment.
//
// Without this wiring, the Challenger's phase-1 instructions to consult a
// TWE's common_defenses / common_false_positives are unsourced: those
// fields render from CasePack, which is built from
// planner.RunConfig.TWEPlaybooks (§24 "Case Pack"), and a nil/empty map
// there means every Case Pack carries those two fields empty regardless of
// what the playbook YAML says.
//
// catalog may be nil (a knowledge root with no playbook directory, the same
// case runL3Planner already tolerates for the twe_playbook_detail action);
// the result is then an empty, non-nil map so callers do not need a nil
// check.
func buildTWEPlaybookSummaries(catalog *twecontext.Catalog) map[string]planner.TWEPlaybookSummary {
	out := make(map[string]planner.TWEPlaybookSummary)
	if catalog == nil {
		return out
	}
	for _, p := range catalog.All() {
		out[p.ID] = planner.TWEPlaybookSummary{
			CommonDefenses:       p.CommonDefenses,
			CommonFalsePositives: p.CommonFalsePositives,
		}
	}
	return out
}
