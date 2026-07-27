package pipeline_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// archWireJSON is a minimal valid ArchitectureModel wire response reused
// from internal/architecture's LLM test: one manifest-kind component. The
// citation validator downgrades it when the cited file is absent, which is
// fine — architecture.Run still succeeds and persists the model.
const archWireJSON = `{
  "parties": [], "roles": [], "assets": [], "trust_zones": [], "entrypoints": [],
  "boundaries": [], "data_flows": [], "state_lifecycles": [],
  "trust_assumptions": [], "deployment_assumptions": [], "unknowns": [],
  "components": [
    {
      "id": "component-enclave-manifest",
      "kind": "manifest",
      "name": "SGX enclave configuration",
      "state": "observed",
      "evidence": [{"kind": "manifest", "file": "enclave.config.xml"}]
    }
  ]
}`

// invariantWireJSON is a minimal valid ProjectInvariants wire response reused
// from internal/invariants's LLM test: one schema-valid invariant.
const invariantWireJSON = `{
  "invariants": [
    {
      "invariant_id": "INV-STATE-001",
      "statement": "Restored WalletState must be checked against a freshness anchor before SignTransaction",
      "related_twes": ["TWE-STATE-001"],
      "entrypoints": ["restore_wallet"],
      "authority_points": ["sign_transaction"],
      "verification_plan": ["trace freshness anchor propagation"]
    }
  ]
}`

// plannerDoneJSON drives the L3 planner to terminate on its first round with
// an empty candidate list and no investigations. With neither half of the
// done payload populated the planner returns no case packs, so
// cases.Enrich -> expert -> challenger -> verifier -> arbiter run with empty
// inputs and make ZERO further LLM calls — the pipeline completes with empty
// findings. Used both as the queued planner response and as the Default so
// any extra planner rounds also terminate immediately.
const plannerDoneJSON = `{"thought":"done","actions":[{"name":"done","args":{"summary":"none","candidates":[],"investigations":[]}}]}`

// TestPipelineEndToEnd_FakeClient exercises the RunWithClient injection seam:
// the whole llm-mode pipeline is driven by a deterministic fake client rather
// than a real LLM. The fake answers, in call order:
//  1. architecture.Run   -> archWireJSON
//  2. invariants.Run      -> invariantWireJSON
//  3. L3 planner round 1  -> plannerDoneJSON (terminate, no candidates)
//
// and Default is plannerDoneJSON so any additional planner rounds also
// terminate. Because the planner yields zero candidates, the downstream
// 4-agent chain (expert/challenger/verifier/arbiter) runs on empty inputs and
// issues no further LLM calls. This is a plumbing/seam test: it asserts the
// pipeline runs to completion and writes its structural artifacts.
func TestPipelineEndToEnd_FakeClient(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve current file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	outputDir := t.TempDir()
	knowledgeRoot := filepath.Join(outputDir, "knowledge")

	cfg := config.Config{
		Command:       "run",
		Target:        filepath.Join(root, "testdata", "sample_repo"),
		Mode:          "llm",
		Focus:         "runtime",
		RunID:         "pipeline-test-001",
		OutputDir:     outputDir,
		KnowledgeRoot: knowledgeRoot,
		MaxHotspots:   4,
		MaxCases:      4,
		StaticTools:   "auto",
	}

	fake := &llmtest.FakeClient{
		Responses: []string{
			archWireJSON,
			invariantWireJSON,
			plannerDoneJSON,
		},
		Default: plannerDoneJSON,
	}

	runDir, err := pipeline.RunWithClient(cfg, fake)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	// Structural artifacts the llm-mode pipeline must produce. GraphPath is
	// intentionally NOT asserted: graph.json is written only by the legacy
	// scanner branch (legacy mode), never in llm mode.
	for _, path := range []string{
		runfs.ProjectProfilePath(runDir),
		// The Project Understanding Layer is wired into the main pipeline: a
		// run must produce the architecture model and project invariants
		// between preprocess and the planner stage.
		runfs.ArchitectureModelPath(runDir),
		runfs.ProjectInvariantsPath(runDir),
		// The arbiter always writes its findings collection, even when the
		// planner produced zero candidates and there is nothing to report.
		runfs.ArbiterFindingsPath(runDir),
	} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("expected artifact %s: %v", path, statErr)
		}
	}

	// The invariant the fake produced must have reached the persisted
	// collection — proves the architecture + invariants seam actually ran
	// the injected client rather than short-circuiting.
	var invs artifacts.ProjectInvariants
	if err := runfs.ReadJSON(runfs.ProjectInvariantsPath(runDir), &invs); err != nil {
		t.Fatalf("read project invariants: %v", err)
	}
	if len(invs.Invariants) != 1 || invs.Invariants[0].InvariantID != "INV-STATE-001" {
		t.Fatalf("invariants = %+v, want the 1 invariant the fake client produced", invs.Invariants)
	}
}
