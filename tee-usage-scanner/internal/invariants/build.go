package invariants

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
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

// Build dispatches to the LLM or heuristic path, matching the
// heuristic|llm convention the rest of the pipeline uses.
func Build(ctx context.Context, client llm.Client, mode string, in Input, temperature float64) ([]artifacts.ProjectInvariant, error) {
	if strings.EqualFold(mode, "llm") {
		return BuildLLM(ctx, client, in, temperature)
	}
	return BuildHeuristic(in), nil
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
	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: invariantSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: buildUserPrompt(in)},
		},
		Temperature: temperature,
		JSONMode:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("invariants llm generate: %w", err)
	}
	var wire wireResponse
	if err := agentutil.UnmarshalJSONObject(resp.Text, &wire); err != nil {
		return nil, fmt.Errorf("parse invariants json: %w | raw=%s", err, truncateForError(resp.Text, 400))
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

// BuildHeuristic is the non-LLM fallback. Instantiating a general TWE
// scenario into a project-specific obligation (§7.4's actual job) requires
// reading and reasoning about the architecture model's specific
// parties/assets/boundaries — that is exactly the step an LLM-free pass
// cannot do. Rather than fabricate a generic, unfounded invariant per TWE
// (which would defeat the entire "project-specific" point of this agent),
// the heuristic path is intentionally a no-op: it returns no invariants
// when there is no LLM to do the instantiation.
func BuildHeuristic(in Input) []artifacts.ProjectInvariant {
	return nil
}

func truncateForError(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "..."
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
