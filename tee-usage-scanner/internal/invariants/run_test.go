package invariants

import (
	"encoding/json"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/schema"
)

// invariantWireJSON is a minimal valid wireResponse JSON: one invariant with
// a non-empty related_twes and verification_plan (both required by
// project-invariant.v1.json — see its "required" list). BuildLLM parses this
// into a ProjectInvariant that Validate/schema.Validate then accept.
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

// TestRun_LLMEndToEnd exercises Run(cfg, client)'s wiring — manifest,
// architecture model, and profile loading, BuildLLM (via a fake client),
// Validate, schema-validation, and persistence — end to end, asserting the
// invariant the fake client produced actually reaches the persisted
// ProjectInvariants collection.
func TestRun_LLMEndToEnd(t *testing.T) {
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

	cfg := config.Config{RunDir: runDir}
	fake := &llmtest.FakeClient{Responses: []string{invariantWireJSON}}
	if err := Run(cfg, fake); err != nil {
		t.Fatalf("Run: %v", err)
	}

	var out artifacts.ProjectInvariants
	if err := runfs.ReadJSON(runfs.ProjectInvariantsPath(runDir), &out); err != nil {
		t.Fatalf("read project invariants: %v", err)
	}
	if out.RunID != "run-inv-test" {
		t.Errorf("run_id = %q", out.RunID)
	}
	if len(out.Invariants) != 1 {
		t.Fatalf("invariants = %+v, want the 1 invariant the fake client produced", out.Invariants)
	}
	if out.Invariants[0].InvariantID != "INV-STATE-001" {
		t.Errorf("invariant_id = %q", out.Invariants[0].InvariantID)
	}
	if out.Invariants[0].Status != "proposed" {
		t.Errorf("status = %q, want proposed (EnforceProposedStatus)", out.Invariants[0].Status)
	}
	if len(fake.Calls) != 1 {
		t.Errorf("expected exactly 1 LLM call, got %d", len(fake.Calls))
	}
}

// A schema-invalid invariant (e.g. one whose statement is empty) must fail
// the schema.Validate call Run(cfg) makes on every invariant before
// persisting — proven directly against schema.Validate here since Run(cfg)
// itself cannot be driven through BuildLLM in a unit test (see
// TestRun_LLMEndToEnd's doc comment).
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
