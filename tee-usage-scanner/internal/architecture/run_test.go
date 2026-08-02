package architecture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// manifestComponentWireJSON is a minimal valid wireModel JSON response: one
// component citing the manifest file path-only (no line range), which
// checkEvidence accepts on existence alone for "manifest"-kind evidence (see
// fileIsSufficientEvidence in validate.go). Both Run tests below reuse this
// exact canned response — the difference between them is whether the cited
// file actually exists in the test's repo checkout, which is exactly what
// ValidateAndDowngrade is meant to catch regardless of build mode.
const manifestComponentWireJSON = `{
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

// TestRun_LLMEndToEnd exercises the full Run(cfg, client) path against a
// throwaway run dir + repo checkout: manifest read,
// BuildLLM (via a fake client), NormalizeStates,
// ValidateAndDowngrade, schema.Validate, and both output files written.
func TestRun_LLMEndToEnd(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoRoot, "enclave.config.xml"), []byte("<EnclaveConfiguration/>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runDir := t.TempDir()
	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "run-arch-test",
		RepoURL: "local", LocalPath: repoRoot, Commit: "abc123",
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{RunDir: runDir}
	fake := &llmtest.FakeClient{Responses: []string{manifestComponentWireJSON}}
	if err := Run(cfg, fake); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var model artifacts.ArchitectureModel
	if err := runfs.ReadJSON(runfs.ArchitectureModelPath(runDir), &model); err != nil {
		t.Fatalf("read architecture model: %v", err)
	}
	if model.SchemaVersion != artifacts.SchemaVersionArchitectureV1 {
		t.Errorf("schema_version = %q", model.SchemaVersion)
	}
	if model.RunID != "run-arch-test" {
		t.Errorf("run_id = %q", model.RunID)
	}
	if len(model.Components) != 1 || model.Components[0].State != artifacts.EvidenceObserved {
		t.Fatalf("components = %+v, want the manifest component to stay observed (its cited file genuinely exists)", model.Components)
	}

	data, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(schema.ArchitectureV1, data); err != nil {
		t.Fatalf("persisted model failed schema validation: %v", err)
	}

	dossier, err := os.ReadFile(runfs.ArchitectureDossierPath(runDir))
	if err != nil {
		t.Fatalf("read dossier: %v", err)
	}
	if len(dossier) == 0 {
		t.Error("dossier is empty")
	}
	if len(fake.Calls) != 1 {
		t.Errorf("expected exactly 1 LLM call, got %d", len(fake.Calls))
	}
}

// A component citing a path that does NOT actually exist under the run's
// repo root must be downgraded before persistence — Run must not skip the
// citation validator regardless of what the LLM returned.
func TestRun_DowngradesFabricatedManifestCitation(t *testing.T) {
	repoRoot := t.TempDir() // no enclave.config.xml written here

	runDir := t.TempDir()
	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "run-arch-test-2",
		RepoURL: "local", LocalPath: repoRoot, Commit: "abc123",
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{RunDir: runDir}
	fake := &llmtest.FakeClient{Responses: []string{manifestComponentWireJSON}}
	if err := Run(cfg, fake); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var model artifacts.ArchitectureModel
	if err := runfs.ReadJSON(runfs.ArchitectureModelPath(runDir), &model); err != nil {
		t.Fatal(err)
	}
	if model.Components[0].State != artifacts.EvidenceUnknown {
		t.Fatalf("state = %q, want unknown — the cited manifest file does not actually exist in this repo checkout", model.Components[0].State)
	}
}
