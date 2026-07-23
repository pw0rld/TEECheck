package architecture

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

// Input is everything the Architecture Agent reads per §7.3: the full TWE
// prior-knowledge context, ProjectProfile, and enough repo identity to
// resolve citations and stamp the output artifact.
type Input struct {
	RunID      string
	Repo       artifacts.RepoRef
	RepoRoot   string
	Profile    artifacts.ProjectProfileV2
	TWEContext string
}

// Build dispatches to the LLM or heuristic path by mode ("llm" or anything
// else, matching the heuristic|llm convention used by expert/challenger/
// verifier). client is unused (and may be nil) in heuristic mode.
func Build(ctx context.Context, client llm.Client, mode string, in Input, temperature float64) (artifacts.ArchitectureModel, error) {
	if strings.EqualFold(mode, "llm") {
		return BuildLLM(ctx, client, in, temperature)
	}
	return BuildHeuristic(in), nil
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
// — ValidateAndDowngrade (validate.go) and ApplyCoverageGuards (coverage.go)
// are the enforcement layer that runs on the result before it is persisted;
// this function's job is prompting and parsing only.
func BuildLLM(ctx context.Context, client llm.Client, in Input, temperature float64) (artifacts.ArchitectureModel, error) {
	if client == nil {
		return artifacts.ArchitectureModel{}, fmt.Errorf("architecture: llm mode requires a client")
	}
	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: architectureSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: buildUserPrompt(in)},
		},
		Temperature: temperature,
		JSONMode:    true,
	})
	if err != nil {
		return artifacts.ArchitectureModel{}, fmt.Errorf("architecture llm generate: %w", err)
	}
	var wire wireModel
	if err := agentutil.UnmarshalJSONObject(resp.Text, &wire); err != nil {
		return artifacts.ArchitectureModel{}, fmt.Errorf("parse architecture model json: %w | raw=%s", err, truncateForError(resp.Text, 400))
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

// BuildHeuristic is the non-LLM fallback. It is deliberately conservative:
// §3.4 is explicit that a keyword hit ("validator", "sgx", ...) is only ever
// a candidate_role/candidate signal, never an architecture fact ("finding
// the word validator cannot assert that component IS the validator"). A
// heuristic pass has no way to ground a keyword hit beyond the hit itself,
// so promoting profile signals straight to observed roles/components/assets
// would violate exactly the rule the citation validator exists to enforce.
//
// What IS safe to promote here: a manifest's existence. "this EDL / Gramine
// manifest / TA manifest file exists at this path" is an observable fact
// the Fingerprint scan already proved, and it makes no claim about what the
// manifest means architecturally — that is still ungrounded and stays a
// components-bucket entry with only its bare existence, not a role or trust
// boundary assertion. See checkEvidence in validate.go for why a path-only
// citation (no line number) validates on existence alone.
//
// Every other signal category (candidate roles, trust artifacts, boundary
// signals, state signals) becomes an Unknowns entry: the fingerprint saw
// something and the model cannot ground it without an LLM (or a human) to
// read the surrounding code, so it is surfaced as exactly that — unknown,
// not silently dropped and not guessed into a stronger state.
func BuildHeuristic(in Input) artifacts.ArchitectureModel {
	model := artifacts.ArchitectureModel{}

	for _, m := range in.Profile.Manifests {
		model.Components = append(model.Components, artifacts.ArchitectureElement{
			ID:          "component-" + m.ID,
			Kind:        "manifest",
			Name:        m.Name,
			Description: fmt.Sprintf("Manifest file observed by the Fingerprint scan: %s", m.Scope),
			State:       artifacts.EvidenceObserved,
			Confidence:  "candidate",
			Evidence:    m.Evidence,
		})
	}

	unknownGroups := [][]artifacts.ProfileSignal{
		in.Profile.TEEPlatforms,
		in.Profile.CandidateRoles,
		in.Profile.TrustArtifacts,
		in.Profile.BoundarySignals,
		in.Profile.StateSignals,
	}
	for _, group := range unknownGroups {
		for _, sig := range group {
			model.Unknowns = append(model.Unknowns, artifacts.ArchitectureElement{
				ID:          "unknown-" + sig.ID,
				Kind:        sig.Kind,
				Name:        sig.Name,
				Description: "Fingerprint candidate signal; not grounded into an architecture fact by the heuristic (non-LLM) Architecture Agent — see BuildHeuristic's doc comment.",
				State:       artifacts.EvidenceUnknown,
				Evidence:    sig.Evidence,
			})
		}
	}

	if len(in.Profile.CoverageWarnings) > 0 {
		model.Unknowns = append(model.Unknowns, artifacts.ArchitectureElement{
			ID:          "unknown-fingerprint-coverage",
			Kind:        "coverage_gap",
			Name:        "Fingerprint coverage warnings",
			Description: "Fingerprint scan coverage warnings: " + strings.Join(in.Profile.CoverageWarnings, "; "),
			State:       artifacts.EvidenceUnknown,
		})
	}

	return model
}

func truncateForError(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "..."
}

// marshalCondensed renders v as indented JSON, truncated to maxChars so a
// large ProjectProfileV2 does not blow the prompt budget. Mirrors
// tee-audit's dossier.py truncation (fp_context[:3000]).
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
