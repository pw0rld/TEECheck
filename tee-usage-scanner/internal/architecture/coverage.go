package architecture

import "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"

// manifestCoverageGapID is the deterministic ID ApplyCoverageGuards uses so
// repeated calls (or an LLM that already added its own note) do not produce
// duplicate entries.
const manifestCoverageGapID = "unknown-manifest-coverage-gap"

// ApplyCoverageGuards is a pure, model-independent guard for §22's manifest
// requirement: "PR-03 measured that 36 of 44 benchmark datasets produce
// zero manifest signals, because the datasets are partial checkouts... the
// agent must therefore route manifest absence into CoverageWarnings/unknown
// and must not conclude anything from it (e.g. 'no declared trust
// boundary')."
//
// It runs unconditionally — in both heuristic and LLM mode, and regardless
// of what the model said — so the coverage gap is recorded even if a live
// model ignores its prompt instructions. It only ever appends an unknowns
// entry; it never removes or reinterprets anything the model produced. The
// complementary half of the requirement ("must not conclude anything from
// it") is enforced structurally by ValidateAndDowngrade: any Boundaries/
// TrustZones statement the model marks observed/documented without a valid
// citation — which by construction is every such statement when there are
// no manifests to cite — gets downgraded regardless of what it claims, so a
// fabricated "no trust boundary" conclusion cannot survive as observed
// either way.
func ApplyCoverageGuards(model artifacts.ArchitectureModel, profile artifacts.ProjectProfileV2) artifacts.ArchitectureModel {
	if len(profile.Manifests) > 0 {
		return model
	}
	for _, u := range model.Unknowns {
		if u.ID == manifestCoverageGapID {
			return model
		}
	}
	model.Unknowns = append(model.Unknowns, artifacts.ArchitectureElement{
		ID:   manifestCoverageGapID,
		Kind: "coverage_gap",
		Name: "Manifest coverage",
		Description: "No manifests (EDL, Gramine manifest, enclave config, TA manifest, " +
			"deployment YAML, ...) were observed by the Fingerprint scan. This may mean the " +
			"repository genuinely declares none, or that this checkout is partial. Absence of " +
			"manifest evidence must not be read as absence of a trust boundary (§3.4/§7.3/§22).",
		State: artifacts.EvidenceUnknown,
	})
	return model
}
