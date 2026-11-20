package arbiter

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// caseContext mirrors the sibling caseContext types in
// internal/expert / internal/challenger / internal/verifier — the
// PR-07 evidence a Case Pack alone does not carry. The Arbiter uses
// it only to RENDER the "anchored ToolFacts" / "architecture evidence
// status" / "invariant verification status" packet sections (§7.9) —
// it never re-derives a verdict from it. All loads are tolerant of a
// missing file, per internal/architecture.Run's precedent.
type caseContext struct {
	archModel        *artifacts.ArchitectureModel
	invariants       []artifacts.ProjectInvariant
	toolFacts        []artifacts.ToolFact
	missingToolFacts []string
}

// loadCaseContext is read-only against
// ArchitectureModel/ProjectInvariants/ToolFacts: only runfs.ReadJSON
// is ever called against any of their paths in this package (§3.5).
func loadCaseContext(runDir string, pack artifacts.CasePack) caseContext {
	var ctx caseContext

	if runfs.LegacyPriorEnabled(runDir) {
		var model artifacts.ArchitectureModel
		if err := runfs.ReadJSON(runfs.ArchitectureModelPath(runDir), &model); err == nil {
			sliced := sliceArchitecture(model, pack.ArchitectureRefs)
			ctx.archModel = &sliced
		}

		if allInvariants, err := runfs.ReadProjectInvariants(runDir); err == nil {
			ctx.invariants = sliceInvariants(allInvariants, pack.RelatedInvariants)
		}
	}

	for _, ref := range pack.ToolFactRefs {
		var fact artifacts.ToolFact
		if err := runfs.ReadJSON(ref, &fact); err != nil {
			ctx.missingToolFacts = append(ctx.missingToolFacts, ref)
			continue
		}
		ctx.toolFacts = append(ctx.toolFacts, fact)
	}

	return ctx
}

// loadIndependentView reads the Challenger's persisted phase-1
// artifact by path (challenge.IndependentViewPath, written by
// internal/challenger.Run). Tolerant of a missing/empty path — an
// older challenge artifact written before PR-07 simply renders an
// empty independent-result section rather than failing the whole
// arbiter stage.
func loadIndependentView(path string) artifacts.ChallengerIndependentView {
	if path == "" {
		return artifacts.ChallengerIndependentView{}
	}
	var view artifacts.ChallengerIndependentView
	_ = runfs.ReadJSON(path, &view)
	return view
}

func sliceArchitecture(model artifacts.ArchitectureModel, refs []string) artifacts.ArchitectureModel {
	want := make(map[string]bool, len(refs))
	for _, r := range refs {
		want[r] = true
	}
	if len(want) == 0 {
		return artifacts.ArchitectureModel{SchemaVersion: model.SchemaVersion, RunID: model.RunID, Repo: model.Repo}
	}

	filterElems := func(in []artifacts.ArchitectureElement) []artifacts.ArchitectureElement {
		var out []artifacts.ArchitectureElement
		for _, e := range in {
			if want[e.ID] {
				out = append(out, e)
			}
		}
		return out
	}
	filterRels := func(in []artifacts.ArchitectureRelation) []artifacts.ArchitectureRelation {
		var out []artifacts.ArchitectureRelation
		for _, r := range in {
			if want[r.ID] {
				out = append(out, r)
			}
		}
		return out
	}

	return artifacts.ArchitectureModel{
		SchemaVersion:         model.SchemaVersion,
		RunID:                 model.RunID,
		Repo:                  model.Repo,
		Parties:               filterElems(model.Parties),
		Components:            filterElems(model.Components),
		Roles:                 filterElems(model.Roles),
		Assets:                filterElems(model.Assets),
		TrustZones:            filterElems(model.TrustZones),
		Entrypoints:           filterElems(model.Entrypoints),
		Boundaries:            filterRels(model.Boundaries),
		DataFlows:             filterRels(model.DataFlows),
		StateLifecycles:       filterRels(model.StateLifecycles),
		TrustAssumptions:      filterElems(model.TrustAssumptions),
		DeploymentAssumptions: filterElems(model.DeploymentAssumptions),
		Unknowns:              filterElems(model.Unknowns),
	}
}

func sliceInvariants(all []artifacts.ProjectInvariant, ids []string) []artifacts.ProjectInvariant {
	if len(ids) == 0 {
		return nil
	}
	byID := make(map[string]artifacts.ProjectInvariant, len(all))
	for _, inv := range all {
		byID[inv.InvariantID] = inv
	}
	var out []artifacts.ProjectInvariant
	for _, id := range ids {
		if inv, ok := byID[id]; ok {
			out = append(out, inv)
		}
	}
	return out
}
