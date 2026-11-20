package expert

import (
	"os"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// caseContext bundles the PR-07 evidence a Case Pack alone does not
// carry: the compiled TWE prior-knowledge text, the relevant
// Architecture Model slice, the relevant Project Invariants, and the
// referenced ToolFacts (§7.6: "输入：相同 TWE 前置知识；当前 Case 相关的
// Architecture slice 和 Project Invariants；Case Pack；原始 ToolFact
// 引用"). Every load is tolerant of a missing file — an older run
// directory, or one where architecture/invariants produced nothing,
// still lets the Expert run against whatever it does have (same
// "migration tolerance" policy internal/architecture.Run already
// uses for a missing TWE context file).
type caseContext struct {
	tweText    string
	archModel  *artifacts.ArchitectureModel
	invariants []artifacts.ProjectInvariant
	toolFacts  []artifacts.ToolFact
	// missingToolFacts lists ToolFactRefs that failed to resolve —
	// surfaced so a prompt/notes section can say "N referenced tool
	// facts unavailable" instead of silently rendering as if the case
	// had none.
	missingToolFacts []string
}

// loadCaseContext reads the run-level TWE context, Architecture
// Model, and Project Invariants once, then narrows Architecture/
// Invariants down to the slice this specific Case Pack references
// (pack.ArchitectureRefs / pack.RelatedInvariants), and resolves
// pack.ToolFactRefs into their persisted ToolFact bodies.
//
// ToolFacts are read-only here: this function never writes to
// runfs.TrustIRToolFactsDir / CodeQLToolFactsDir. §3.5 forbids an
// Agent from rewriting a tool fact; RunWithEvents in run.go only ever
// calls runfs.ReadJSON against a ToolFact path, never WriteJSON.
func loadCaseContext(runDir string, pack artifacts.CasePack) caseContext {
	var ctx caseContext

	if data, err := os.ReadFile(runfs.TWEAgentContextPath(runDir)); err == nil {
		ctx.tweText = string(data)
	}

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

// sliceArchitecture keeps only the elements/relations whose ID
// appears in refs, so the prompt carries the case-relevant slice
// rather than the full run-wide model (CasePack doc comment, §11.3).
// An empty refs list returns an empty model, not the full one — a
// case that named no architecture refs gets no architecture context,
// rather than silently receiving everything.
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

// sliceInvariants keeps only the invariants named in ids. Order
// follows ids so a rendered prompt lists them in the same order the
// Case Pack (and thus the Investigator's reasoning) named them.
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

// maxArchElementsRendered / maxInvariantsRendered bound prompt size,
// mirroring internal/planner/prompt.go's caps for the same reason:
// keep the injected context within a hard token budget rather than
// truncating silently at the LLM provider's own limit.
const (
	maxArchElementsRendered = 40
	maxInvariantsRendered   = 20
)

// renderArchitectureSlice renders a compact, one-line-per-item view
// of an already-narrowed ArchitectureModel. Evidence detail stays in
// the persisted architecture.v1.json; the prompt only needs enough to
// ground the Expert's reasoning against IDs it can cite by name.
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

// renderInvariants renders the sliced invariant list for prompt
// injection: statement, current status, and the guards/defenses
// expected of the code, so the Expert can reason about what "should"
// hold rather than re-deriving it from the TWE catalog each time.
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

// renderToolFacts renders the ToolFacts a Case Pack referenced.
// Read-only presentation: the fact_id is included so a claim can cite
// it, but nothing here round-trips back into the ToolFact file.
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
