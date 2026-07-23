package architecture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// TestRun_HeuristicEndToEnd exercises the full Run(cfg) path against a
// throwaway run dir + repo checkout: manifest -> ProjectProfileV2 read,
// BuildHeuristic, NormalizeStates, ApplyCoverageGuards,
// ValidateAndDowngrade, schema.Validate, and both output files written.
func TestRun_HeuristicEndToEnd(t *testing.T) {
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
	profile := artifacts.ProjectProfileV2{
		SchemaVersion: artifacts.SchemaVersionProjectProfileV2, RunID: "run-arch-test",
		Repo: artifacts.RepoRef{URL: "local", Commit: "abc123"},
		Manifests: []artifacts.ProfileSignal{{
			ID: "manifest:enclave.config.xml", Kind: "manifest", Name: "SGX enclave configuration",
			Scope:    "enclave.config.xml",
			Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: "enclave.config.xml"}},
		}},
	}
	if err := runfs.WriteJSON(runfs.ContextProjectProfilePath(runDir), profile); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, Mode: "heuristic"}
	if err := Run(cfg); err != nil {
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
		t.Fatalf("components = %+v, want the manifest promoted to an observed component (its file genuinely exists)", model.Components)
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
}

// A manifest citing a path that does NOT actually exist under the run's
// repo root must be downgraded before persistence — Run must not skip the
// citation validator for the heuristic path.
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
	profile := artifacts.ProjectProfileV2{
		SchemaVersion: artifacts.SchemaVersionProjectProfileV2, RunID: "run-arch-test-2",
		Repo: artifacts.RepoRef{URL: "local", Commit: "abc123"},
		Manifests: []artifacts.ProfileSignal{{
			ID: "manifest:enclave.config.xml", Kind: "manifest", Name: "SGX enclave configuration",
			Scope:    "enclave.config.xml",
			Evidence: []artifacts.EvidenceReference{{Kind: "manifest", File: "enclave.config.xml"}},
		}},
	}
	if err := runfs.WriteJSON(runfs.ContextProjectProfilePath(runDir), profile); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, Mode: "heuristic"}
	if err := Run(cfg); err != nil {
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
