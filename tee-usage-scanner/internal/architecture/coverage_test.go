package architecture

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// §22: "PR-03 measured that 36 of 44 benchmark datasets produce zero
// manifest signals... the agent must therefore route manifest absence
// into CoverageWarnings/unknown and must not conclude anything from it."
func TestApplyCoverageGuards_EmptyManifestsAddsUnknownEntry(t *testing.T) {
	profile := artifacts.ProjectProfileV2{Manifests: nil}
	model := ApplyCoverageGuards(artifacts.ArchitectureModel{}, profile)

	if len(model.Unknowns) != 1 {
		t.Fatalf("Unknowns = %d, want 1", len(model.Unknowns))
	}
	got := model.Unknowns[0]
	if got.State != artifacts.EvidenceUnknown {
		t.Errorf("state = %q, want unknown", got.State)
	}
	if !strings.Contains(got.Description, "must not be read as absence of a trust boundary") {
		t.Errorf("description does not warn against concluding absence: %q", got.Description)
	}
}

func TestApplyCoverageGuards_ManifestsPresentAddsNothing(t *testing.T) {
	profile := artifacts.ProjectProfileV2{
		Manifests: []artifacts.ProfileSignal{{ID: "manifest:enclave.config.xml", Kind: "manifest", Name: "SGX enclave configuration"}},
	}
	model := ApplyCoverageGuards(artifacts.ArchitectureModel{}, profile)
	if len(model.Unknowns) != 0 {
		t.Fatalf("Unknowns = %+v, want none when manifests were observed", model.Unknowns)
	}
}

func TestApplyCoverageGuards_IdempotentNoDuplicateEntry(t *testing.T) {
	profile := artifacts.ProjectProfileV2{Manifests: nil}
	model := ApplyCoverageGuards(artifacts.ArchitectureModel{}, profile)
	model = ApplyCoverageGuards(model, profile)
	if len(model.Unknowns) != 1 {
		t.Fatalf("Unknowns = %d, want 1 (no duplicate on repeated application)", len(model.Unknowns))
	}
}

// The guard must fire regardless of what the model itself produced —
// even if the model already emitted (wrong) Boundaries claiming
// certainty, the coverage gap is still recorded.
func TestApplyCoverageGuards_FiresEvenWhenModelClaimedBoundaries(t *testing.T) {
	profile := artifacts.ProjectProfileV2{Manifests: nil}
	model := artifacts.ArchitectureModel{
		Boundaries: []artifacts.ArchitectureRelation{{
			ID: "boundary-1", Kind: "trust_boundary", From: "party-host", To: "component-enclave",
			State: artifacts.EvidenceObserved, Description: "no trust boundary declared",
		}},
	}
	model = ApplyCoverageGuards(model, profile)
	if len(model.Unknowns) != 1 {
		t.Fatalf("Unknowns = %d, want 1 even though the model already produced Boundaries", len(model.Unknowns))
	}
	// The fabricated Boundaries entry above has no evidence at all, so
	// ValidateAndDowngrade (run separately in the real pipeline) is what
	// actually strips its unearned "observed" claim — ApplyCoverageGuards
	// itself never touches Boundaries/TrustZones, only appends to Unknowns.
	if model.Boundaries[0].State != artifacts.EvidenceObserved {
		t.Fatalf("ApplyCoverageGuards must not itself rewrite Boundaries — that is ValidateAndDowngrade's job")
	}
}
