package invariants

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// Input is everything the Invariant Agent reads per §7.4: the full TWE
// prior-knowledge context, the already-validated ArchitectureModel, and
// ProjectProfile evidence.
type Input struct {
	RunID      string
	Model      artifacts.ArchitectureModel
	Profile    artifacts.ProjectProfileV2
	TWEContext string
}

// wireInvariant is the LLM's response shape for one invariant. It omits
// schema_version (this package stamps it) and status (EnforceProposedStatus
// always overwrites it — see the package doc comment) so nothing the model
// writes for those two fields is ever read.
type wireInvariant struct {
	InvariantID           string                        `json:"invariant_id"`
	Statement             string                        `json:"statement"`
	RelatedTWEs           []string                      `json:"related_twes"`
	Parties               []string                      `json:"parties"`
	Assets                []string                      `json:"assets"`
	Boundaries            []string                      `json:"boundaries"`
	Entrypoints           []string                      `json:"entrypoints"`
	AuthorityPoints       []string                      `json:"authority_points"`
	RequiredProperties    []string                      `json:"required_properties"`
	ExpectedDefenses      []string                      `json:"expected_defenses"`
	ArchitectureRefs      []string                      `json:"architecture_refs"`
	VerificationPlan      []string                      `json:"verification_plan"`
	UnresolvedAssumptions []string                      `json:"unresolved_assumptions"`
	Evidence              []artifacts.EvidenceReference `json:"evidence"`
}

type wireResponse struct {
	Invariants []wireInvariant `json:"invariants"`
}

// BuildLLM calls the configured LLM once and parses its response. Like
// architecture.BuildLLM, it does not itself enforce any §22 constraint —
// EnforceProposedStatus, ApplyCatalogGap, ValidateArchitectureRefs and
// ValidateEvidence (validate.go) are the enforcement layer that runs on the
// result before persistence.
func BuildLLM(ctx context.Context, client llm.Client, in Input, temperature float64) ([]artifacts.ProjectInvariant, error) {
	if client == nil {
		return nil, fmt.Errorf("invariants: llm mode requires a client")
	}
	// llm.GenerateJSON re-asks once if the reply is not a JSON object; a
	// single format wobble no longer costs the whole run. See its doc comment
	// for the bound.
	var wire wireResponse
	if _, err := llm.GenerateJSON(ctx, client, "invariants", llm.GenerateRequest{
		SystemPrompt: invariantSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: buildUserPrompt(in)},
		},
		Temperature: temperature,
		JSONMode:    true,
	}, &wire); err != nil {
		return nil, err
	}
	out := make([]artifacts.ProjectInvariant, 0, len(wire.Invariants))
	for _, w := range wire.Invariants {
		out = append(out, artifacts.ProjectInvariant{
			InvariantID:           w.InvariantID,
			Statement:             w.Statement,
			RelatedTWEs:           w.RelatedTWEs,
			Parties:               w.Parties,
			Assets:                w.Assets,
			Boundaries:            w.Boundaries,
			Entrypoints:           w.Entrypoints,
			AuthorityPoints:       w.AuthorityPoints,
			RequiredProperties:    w.RequiredProperties,
			ExpectedDefenses:      w.ExpectedDefenses,
			ArchitectureRefs:      w.ArchitectureRefs,
			VerificationPlan:      w.VerificationPlan,
			UnresolvedAssumptions: w.UnresolvedAssumptions,
			Evidence:              w.Evidence,
			// Status is deliberately NOT copied from the wire shape — see
			// the package doc comment and EnforceProposedStatus.
		})
	}
	return out, nil
}

func marshalCondensed(v any, maxChars int) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("<failed to render: %v>", err)
	}
	s := string(data)
	if len(s) > maxChars {
		return s[:maxChars] + "\n...[truncated]"
	}
	return s
}
