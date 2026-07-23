package invariants

import (
	"encoding/json"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// TestRun_HeuristicEndToEnd exercises Run(cfg)'s wiring — manifest,
// architecture model, and profile loading, and persistence — in heuristic
// mode. BuildHeuristic is a deliberate no-op (see its doc comment), so this
// proves the plumbing writes a valid, empty collection rather than proving
// invariant *content*, which is llm-mode-only and covered directly via
// BuildLLM/Validate in build_test.go and rollback_test.go (Run(cfg) itself
// cannot be unit-tested in llm mode without a live model — same limitation
// expert.Run has, see internal/expert/run_test.go).
func TestRun_HeuristicEndToEnd(t *testing.T) {
	runDir := t.TempDir()
	manifest := artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1", RunID: "run-inv-test",
		RepoURL: "local", LocalPath: t.TempDir(), Commit: "abc123",
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(runDir), manifest); err != nil {
		t.Fatal(err)
	}
	model := artifacts.ArchitectureModel{
		SchemaVersion: artifacts.SchemaVersionArchitectureV1, RunID: "run-inv-test",
		Repo: artifacts.RepoRef{URL: "local", Commit: "abc123"},
	}
	if err := runfs.WriteJSON(runfs.ArchitectureModelPath(runDir), model); err != nil {
		t.Fatal(err)
	}
	profile := artifacts.ProjectProfileV2{SchemaVersion: artifacts.SchemaVersionProjectProfileV2, RunID: "run-inv-test"}
	if err := runfs.WriteJSON(runfs.ContextProjectProfilePath(runDir), profile); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{RunDir: runDir, Mode: "heuristic"}
	if err := Run(cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var out artifacts.ProjectInvariants
	if err := runfs.ReadJSON(runfs.ProjectInvariantsPath(runDir), &out); err != nil {
		t.Fatalf("read project invariants: %v", err)
	}
	if out.RunID != "run-inv-test" {
		t.Errorf("run_id = %q", out.RunID)
	}
	if len(out.Invariants) != 0 {
		t.Errorf("invariants = %+v, want none (heuristic mode is a no-op)", out.Invariants)
	}
}

// A schema-invalid invariant (e.g. one whose statement is empty) must fail
// the schema.Validate call Run(cfg) makes on every invariant before
// persisting — proven directly against schema.Validate here since Run(cfg)
// itself cannot be driven through BuildLLM in a unit test (see
// TestRun_HeuristicEndToEnd's doc comment).
func TestSchemaValidation_RejectsEmptyStatement(t *testing.T) {
	inv := artifacts.ProjectInvariant{
		SchemaVersion: artifacts.SchemaVersionProjectInvariantV1,
		InvariantID:   "INV-1", Statement: "",
		RelatedTWEs: []string{"TWE-STATE-001"}, VerificationPlan: []string{},
		Status: "proposed",
	}
	inv, _ = Validate(inv, artifacts.ArchitectureModel{}, t.TempDir())
	if inv.Statement != "" {
		t.Fatalf("Validate must not fabricate a statement: %q", inv.Statement)
	}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(schema.ProjectInvariantV1, data); err == nil {
		t.Fatal("expected an empty statement to be rejected by project-invariant.v1.json")
	}
}
