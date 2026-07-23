package architecture

import (
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

// RenderDossier produces the human-readable Markdown view of model. Per
// §9.2 ("Markdown Dossier 从该模型派生，不是另一份权威数据"), this function
// is the ONLY place architecture_dossier.md text comes from — it reads
// fields off the already-validated ArchitectureModel and formats them,
// it never adds a fact the model does not already have. adjustments is
// rendered as its own section specifically so a reader who wants to know
// "what did the citation validator change" does not have to diff the raw
// JSON against LLM logs.
func RenderDossier(model artifacts.ArchitectureModel, adjustments []StateAdjustment) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Architecture Dossier\n\n")
	fmt.Fprintf(&b, "Derived from architecture.v1.json (run %s). This file is a presentation view; the JSON model is authoritative — see §9.2.\n\n", model.RunID)

	renderElementSection(&b, "Parties", model.Parties)
	renderElementSection(&b, "Components", model.Components)
	renderElementSection(&b, "Roles", model.Roles)
	renderElementSection(&b, "Assets", model.Assets)
	renderElementSection(&b, "Trust Zones", model.TrustZones)
	renderElementSection(&b, "Entrypoints", model.Entrypoints)
	renderRelationSection(&b, "Trust Boundaries", model.Boundaries)
	renderRelationSection(&b, "Data Flows", model.DataFlows)
	renderRelationSection(&b, "State Lifecycles", model.StateLifecycles)
	renderElementSection(&b, "Trust Assumptions", model.TrustAssumptions)
	renderElementSection(&b, "Deployment Assumptions", model.DeploymentAssumptions)
	renderElementSection(&b, "Unknowns", model.Unknowns)

	if len(adjustments) > 0 {
		fmt.Fprintf(&b, "## Citation Validator Adjustments\n\n")
		fmt.Fprintf(&b, "The following statements were downgraded because their citation did not check out (§22):\n\n")
		for _, adj := range adjustments {
			fmt.Fprintf(&b, "- `%s` (%s): %s -> %s — %s\n", adj.ElementID, adj.Bucket, adj.FromState, adj.ToState, adj.Reason)
		}
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

func renderElementSection(b *strings.Builder, title string, elems []artifacts.ArchitectureElement) {
	if len(elems) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", title)
	for _, el := range elems {
		fmt.Fprintf(b, "- **%s** [%s] — %s\n", el.Name, el.State, el.Description)
		for _, ev := range el.Evidence {
			fmt.Fprintf(b, "  - evidence: %s\n", formatEvidence(ev))
		}
		if len(el.Dependencies) > 0 {
			fmt.Fprintf(b, "  - depends on: %s\n", strings.Join(el.Dependencies, ", "))
		}
	}
	fmt.Fprintf(b, "\n")
}

func renderRelationSection(b *strings.Builder, title string, rels []artifacts.ArchitectureRelation) {
	if len(rels) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", title)
	for _, rel := range rels {
		fmt.Fprintf(b, "- **%s -> %s** [%s] — %s\n", rel.From, rel.To, rel.State, rel.Description)
		for _, ev := range rel.Evidence {
			fmt.Fprintf(b, "  - evidence: %s\n", formatEvidence(ev))
		}
		if len(rel.Dependencies) > 0 {
			fmt.Fprintf(b, "  - depends on: %s\n", strings.Join(rel.Dependencies, ", "))
		}
	}
	fmt.Fprintf(b, "\n")
}

func formatEvidence(ev artifacts.EvidenceReference) string {
	if ev.File != "" && ev.StartLine > 0 {
		return fmt.Sprintf("%s:%d-%d", ev.File, ev.StartLine, ev.EndLine)
	}
	if ev.File != "" {
		return ev.File
	}
	if ev.ArtifactRef != "" {
		return "artifact:" + ev.ArtifactRef
	}
	return "(no location)"
}
