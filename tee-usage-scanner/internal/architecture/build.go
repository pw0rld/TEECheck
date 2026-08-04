package architecture

import (
	"context"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// Input is everything the Architecture Agent reads per §7.3: the full TWE
// prior-knowledge context and enough repo identity to resolve citations and
// stamp the output artifact.
type Input struct {
	RunID      string
	Repo       artifacts.RepoRef
	RepoRoot   string
	TWEContext string
}

// wireModel is the LLM's response shape. It intentionally reuses the
// canonical bucket types (artifacts.ArchitectureElement/Relation) so the
// model is asked for, and can only produce, exactly the §9.2 contract's
// element/relation shape — there is no separate "LLM-friendly" schema to
// keep in sync with the canonical one.
type wireModel struct {
	Parties               []artifacts.ArchitectureElement  `json:"parties"`
	Components            []artifacts.ArchitectureElement  `json:"components"`
	Roles                 []artifacts.ArchitectureElement  `json:"roles"`
	Assets                []artifacts.ArchitectureElement  `json:"assets"`
	TrustZones            []artifacts.ArchitectureElement  `json:"trust_zones"`
	Entrypoints           []artifacts.ArchitectureElement  `json:"entrypoints"`
	Boundaries            []artifacts.ArchitectureRelation `json:"boundaries"`
	DataFlows             []artifacts.ArchitectureRelation `json:"data_flows"`
	StateLifecycles       []artifacts.ArchitectureRelation `json:"state_lifecycles"`
	TrustAssumptions      []artifacts.ArchitectureElement  `json:"trust_assumptions"`
	DeploymentAssumptions []artifacts.ArchitectureElement  `json:"deployment_assumptions"`
	Unknowns              []artifacts.ArchitectureElement  `json:"unknowns"`
}

// BuildLLM calls the configured LLM once and parses its response directly
// into the canonical bucket shapes. It does not itself decide what is true
// — ValidateAndDowngrade (validate.go)
// are the enforcement layer that runs on the result before it is persisted;
// this function's job is prompting and parsing only.
func BuildLLM(ctx context.Context, client llm.Client, in Input, temperature float64) (artifacts.ArchitectureModel, error) {
	if client == nil {
		return artifacts.ArchitectureModel{}, fmt.Errorf("architecture: llm mode requires a client")
	}
	// llm.GenerateJSON re-asks once if the reply is not a JSON object; a
	// single format wobble no longer costs the whole run. See its doc comment
	// for the bound.
	var wire wireModel
	if _, err := llm.GenerateJSON(ctx, client, "architecture model", llm.GenerateRequest{
		SystemPrompt: architectureSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: buildUserPrompt(in)},
		},
		Temperature: temperature,
		JSONMode:    true,
	}, &wire); err != nil {
		return artifacts.ArchitectureModel{}, err
	}
	return artifacts.ArchitectureModel{
		Parties:               wire.Parties,
		Components:            wire.Components,
		Roles:                 wire.Roles,
		Assets:                wire.Assets,
		TrustZones:            wire.TrustZones,
		Entrypoints:           wire.Entrypoints,
		Boundaries:            wire.Boundaries,
		DataFlows:             wire.DataFlows,
		StateLifecycles:       wire.StateLifecycles,
		TrustAssumptions:      wire.TrustAssumptions,
		DeploymentAssumptions: wire.DeploymentAssumptions,
		Unknowns:              wire.Unknowns,
	}, nil
}
