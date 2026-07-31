package verifier

import (
	"os"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// caseContext mirrors internal/expert's and internal/challenger's —
// the PR-07 evidence a Case Pack alone does not carry: compiled TWE
// prior knowledge, the relevant Architecture Model slice, the
// relevant Project Invariants (full objects, not just IDs, so the
// Verifier can compare current Status/ExpectedDefenses against what
// it is about to conclude), and the referenced ToolFacts.
//
// All loads are tolerant of a missing file, same policy
// internal/architecture.Run uses for a missing TWE context file.
type caseContext struct {
	tweText          string
	archModel        *artifacts.ArchitectureModel
	invariants       []artifacts.ProjectInvariant
	toolFacts        []artifacts.ToolFact
	missingToolFacts []string
}

// loadCaseContext is read-only against ToolFacts and
// project_invariants.v1.json: only runfs.ReadJSON is ever called
// against either path in this package. The Verifier's proposed
// status changes are appended to a separate log by appendInvariantUpdates
// (see updates.go) — this function never writes anything (§3.5).
func loadCaseContext(runDir string, pack artifacts.CasePack) caseContext {
	var ctx caseContext

	if data, err := os.ReadFile(runfs.TWEAgentContextPath(runDir)); err == nil {
		ctx.tweText = string(data)
	}

	var model artifacts.ArchitectureModel
	if err := runfs.ReadJSON(runfs.ArchitectureModelPath(runDir), &model); err == nil {
		sliced := sliceArchitecture(model, pack.ArchitectureRefs)
		ctx.archModel = &sliced
	}

	if allInvariants, err := runfs.ReadProjectInvariants(runDir); err == nil {
		ctx.invariants = sliceInvariants(allInvariants, pack.RelatedInvariants)
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

const (
	maxArchElementsRendered = 40
	maxInvariantsRendered   = 20
)

func renderArchitectureSlice(model *artifacts.ArchitectureModel) string {
	if model == nil {
		return "- none"
	}
	var lines []string
	addElems := func(bucket string, elems []artifacts.ArchitectureElement) {
		for _, e := range elems {
			lines = append(lines, "- ["+bucket+"] "+e.ID+" ("+string(e.State)+"): "+e.Name+" — "+e.Description)
		}
	}
	addRels := func(bucket string, rels []artifacts.ArchitectureRelation) {
		for _, r := range rels {
			lines = append(lines, "- ["+bucket+"] "+r.ID+" ("+string(r.State)+"): "+r.From+" -> "+r.To+" — "+r.Description)
		}
	}
	addElems("party", model.Parties)
	addElems("component", model.Components)
	addElems("role", model.Roles)
	addElems("asset", model.Assets)
	addElems("trust_zone", model.TrustZones)
	addElems("entrypoint", model.Entrypoints)
	addRels("boundary", model.Boundaries)
	addRels("data_flow", model.DataFlows)
	addRels("state_lifecycle", model.StateLifecycles)
	addElems("trust_assumption", model.TrustAssumptions)
	addElems("deployment_assumption", model.DeploymentAssumptions)
	addElems("unknown", model.Unknowns)

	if len(lines) == 0 {
		return "- none"
	}
	if len(lines) > maxArchElementsRendered {
		lines = lines[:maxArchElementsRendered]
		lines = append(lines, "- ... (truncated; see the run's architecture.v1.json for the full model)")
	}
	return strings.Join(lines, "\n")
}

func renderInvariants(invs []artifacts.ProjectInvariant) string {
	if len(invs) == 0 {
		return "- none"
	}
	n := len(invs)
	truncated := n > maxInvariantsRendered
	if truncated {
		n = maxInvariantsRendered
	}
	var lines []string
	for _, inv := range invs[:n] {
		lines = append(lines, "- "+inv.InvariantID+" ["+inv.Status+"]: "+inv.Statement+
			" (required: "+strings.Join(inv.RequiredProperties, ", ")+
			"; expected defenses: "+strings.Join(inv.ExpectedDefenses, ", ")+")")
	}
	if truncated {
		lines = append(lines, "- ... (truncated; see the run's project_invariants.v1.json for the rest)")
	}
	return strings.Join(lines, "\n")
}

func renderToolFacts(facts []artifacts.ToolFact, missing []string) string {
	if len(facts) == 0 && len(missing) == 0 {
		return "- none"
	}
	var lines []string
	for _, f := range facts {
		lines = append(lines, "- "+artifacts.FormatToolFact(f))
	}
	for _, ref := range missing {
		lines = append(lines, "- (unavailable) "+ref)
	}
	return strings.Join(lines, "\n")
}
