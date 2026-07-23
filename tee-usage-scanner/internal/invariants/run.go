package invariants

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// schemaVersionProjectInvariantsCollection tags the persisted collection
// file, distinct from artifacts.SchemaVersionProjectInvariantV1 (which
// project-invariant.v1.json requires on each individual invariant object).
// There is no eighth-contract schema for the collection wrapper itself —
// project-invariant.v1.json describes one invariant (§9.3) — so each
// element is schema-validated on its own below, matching how
// artifacts.Findings' "teecheck.findings.v2" wrapper tag is likewise
// distinct from the per-item FindingItem/UnifiedFindingV3 schema version.
const schemaVersionProjectInvariantsCollection = "teecheck.project_invariants.v1"

// Run is the standalone entry point for the Invariant Agent stage: it reads
// the ArchitectureModel a prior architecture.Run already validated, the
// ProjectProfileV2, and the compiled TWE prior-knowledge context, builds
// ProjectInvariant[], runs each through Validate, schema-validates each one
// individually (project-invariant.v1.json describes a single invariant, not
// the collection — see the doc comment on artifacts.ProjectInvariants), and
// persists the collection.
func Run(cfg config.Config) error {
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	var model artifacts.ArchitectureModel
	if err := runfs.ReadJSON(runfs.ArchitectureModelPath(cfg.RunDir), &model); err != nil {
		return fmt.Errorf("load architecture model: %w", err)
	}

	var profile artifacts.ProjectProfileV2
	if err := runfs.ReadJSON(runfs.ContextProjectProfilePath(cfg.RunDir), &profile); err != nil {
		return fmt.Errorf("load project profile v2: %w", err)
	}

	tweContext := ""
	if data, err := os.ReadFile(runfs.TWEAgentContextPath(cfg.RunDir)); err == nil {
		tweContext = string(data)
	}

	var client llm.Client
	if strings.EqualFold(cfg.Mode, "llm") {
		client = llm.NewClient(cfg)
	}

	in := Input{RunID: manifest.RunID, Model: model, Profile: profile, TWEContext: tweContext}
	built, err := Build(context.Background(), client, cfg.Mode, in, cfg.LLMTemp)
	if err != nil {
		return fmt.Errorf("build invariants: %w", err)
	}

	invariants := make([]artifacts.ProjectInvariant, 0, len(built))
	totalAdjustments := 0
	for _, inv := range built {
		inv.SchemaVersion = artifacts.SchemaVersionProjectInvariantV1
		inv, adjustments := Validate(inv, model, manifest.LocalPath)
		totalAdjustments += len(adjustments)

		data, err := json.Marshal(inv)
		if err != nil {
			return fmt.Errorf("marshal invariant %s: %w", inv.InvariantID, err)
		}
		if err := schema.Validate(schema.ProjectInvariantV1, data); err != nil {
			return fmt.Errorf("invariant %s failed schema validation: %w", inv.InvariantID, err)
		}
		invariants = append(invariants, inv)
	}

	out := artifacts.ProjectInvariants{
		SchemaVersion: schemaVersionProjectInvariantsCollection,
		RunID:         manifest.RunID,
		Invariants:    invariants,
	}
	if err := runfs.WriteJSON(runfs.ProjectInvariantsPath(cfg.RunDir), out); err != nil {
		return fmt.Errorf("write project invariants: %w", err)
	}

	fmt.Printf("Project invariants written to %s (%d invariant(s), %d adjustment(s))\n",
		runfs.ProjectInvariantsPath(cfg.RunDir), len(invariants), totalAdjustments)
	return nil
}
