package architecture

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func TestRenderDossier_DerivedFromModelOnly(t *testing.T) {
	model := artifacts.ArchitectureModel{
		RunID: "run-1",
		Assets: []artifacts.ArchitectureElement{{
			ID: "asset-1", Name: "WalletState", State: artifacts.EvidenceObserved, Description: "sealed wallet state",
			Evidence: []artifacts.EvidenceReference{{File: "state.rs", StartLine: 10, EndLine: 20}},
		}},
		Boundaries: []artifacts.ArchitectureRelation{{
			ID: "boundary-1", From: "party-host", To: "asset-1", State: artifacts.EvidenceInferred,
			Dependencies: []string{"asset-1"},
		}},
	}
	doc := RenderDossier(model, nil)

	for _, want := range []string{"run-1", "WalletState", "sealed wallet state", "state.rs:10-20", "party-host -> asset-1", "depends on: asset-1"} {
		if !strings.Contains(doc, want) {
			t.Errorf("dossier missing %q:\n%s", want, doc)
		}
	}
}

func TestRenderDossier_AdjustmentsSectionRendersWhenPresent(t *testing.T) {
	model := artifacts.ArchitectureModel{}
	adjustments := []StateAdjustment{{
		Bucket: "assets", ElementID: "asset-1",
		FromState: artifacts.EvidenceObserved, ToState: artifacts.EvidenceUnknown,
		Reason: "citation did not resolve: citation: file not found: missing.rs",
	}}
	doc := RenderDossier(model, adjustments)
	if !strings.Contains(doc, "Citation Validator Adjustments") {
		t.Error("adjustments section missing")
	}
	if !strings.Contains(doc, "asset-1") || !strings.Contains(doc, "observed -> unknown") {
		t.Errorf("adjustment detail missing from dossier:\n%s", doc)
	}
}

func TestRenderDossier_NoAdjustmentsSectionWhenNoneOccurred(t *testing.T) {
	doc := RenderDossier(artifacts.ArchitectureModel{}, nil)
	if strings.Contains(doc, "Citation Validator Adjustments") {
		t.Error("adjustments section should be omitted when there were no downgrades")
	}
}
