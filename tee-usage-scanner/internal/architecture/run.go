package architecture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// Run is the standalone entry point for the Architecture Agent stage: it
// reads the compiled TWE prior-knowledge context a prior preprocessor.Run
// already wrote to runDir, builds an ArchitectureModel via the injected
// client, runs it through the citation validator, schema-validates the
// result, and persists both the JSON model and its derived Markdown dossier.
func Run(cfg config.Config, client llm.Client) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	// The TWE agent context is compiled once by preprocessor.Run and
	// shared read-only by every downstream agent (§11.1: one compile, many
	// injection points). A missing file is tolerated — same "migration
	// tolerance" policy preprocessor.compileTWEKnowledge itself uses for a
	// missing playbook directory — so a run against an older knowledge
	// root still produces an (unknowns-heavy) architecture model instead
	// of hard-failing this stage.
	tweContext := ""
	if data, err := os.ReadFile(runfs.TWEAgentContextPath(cfg.RunDir)); err == nil {
		tweContext = string(data)
	}

	in := Input{
		RunID:      manifest.RunID,
		Repo:       artifacts.RepoRef{URL: manifest.RepoURL, Commit: manifest.Commit, Focus: manifest.Focus},
		RepoRoot:   manifest.LocalPath,
		TWEContext: tweContext,
	}

	model, err := BuildLLM(context.Background(), client, in, cfg.LLMTemp)
	if err != nil {
		return fmt.Errorf("build architecture model: %w", err)
	}
	model.SchemaVersion = artifacts.SchemaVersionArchitectureV1
	model.RunID = in.RunID
	model.Repo = in.Repo

	model, enumAdjustments := NormalizeStates(model)
	model, citationAdjustments := ValidateAndDowngrade(model, manifest.LocalPath)
	adjustments := append(enumAdjustments, citationAdjustments...)

	data, err := json.Marshal(model)
	if err != nil {
		return fmt.Errorf("marshal architecture model: %w", err)
	}
	if err := schema.Validate(schema.ArchitectureV1, data); err != nil {
		return fmt.Errorf("architecture model failed schema validation: %w", err)
	}

	if err := runfs.WriteJSON(runfs.ArchitectureModelPath(cfg.RunDir), model); err != nil {
		return fmt.Errorf("write architecture model: %w", err)
	}
	if err := runfs.WriteText(runfs.ArchitectureDossierPath(cfg.RunDir), RenderDossier(model, adjustments)); err != nil {
		return fmt.Errorf("write architecture dossier: %w", err)
	}

	fmt.Printf("Architecture model written to %s (%d citation/state adjustment(s))\n", runfs.ArchitectureModelPath(cfg.RunDir), len(adjustments))
	return nil
}
