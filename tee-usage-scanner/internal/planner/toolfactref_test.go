package planner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// stubFactLayerQuery stands in for actions.FactLayerQueryHandler: it returns
// the same compact observation shape (that file's factLayerQueryOutput)
// without needing a CodeQL engine or a cloned repository.
type stubFactLayerQuery struct{ ref string }

func (stubFactLayerQuery) Name() string { return "fact_layer_query" }

func (s stubFactLayerQuery) Run(_ context.Context, _ actions.ActionRequest) actions.ActionResult {
	out, err := json.Marshal(map[string]any{
		"tool_fact_ref":  s.ref,
		"status":         "success",
		"operation":      "cpp.state.rollback_version_propagation",
		"location_count": 0,
	})
	if err != nil {
		return actions.ActionResult{Name: "fact_layer_query", OK: false, Error: err.Error()}
	}
	return actions.ActionResult{Name: "fact_layer_query", OK: true, Output: string(out)}
}

// TestPlannerRun_ExecutedToolFactSurvivesAnEmptyDonePayload is the
// CVE-2026-44362 gate run's actual failure, reduced to a unit test.
//
// prompt.go's `done` schema asks the model to echo back the tool_fact_refs it
// used. On 2026-07-30 the fixed-side run called fact_layer_query, was shown
// the ToolFact path in the observation, and then emitted
// `"tool_fact_refs": []` — while its own coverage_gaps said "tool fact layer
// unused" and the ToolFact sat on disk. Every downstream agent reads
// CasePack.ToolFactRefs (expert/challenger/verifier/arbiter context.go), so
// the one immutable-tier artifact the run produced reached none of them.
//
// A ToolFact reference is deterministic output of an action the planner
// itself executed. It must not depend on the model remembering to copy a
// string.
func TestPlannerRun_ExecutedToolFactSurvivesAnEmptyDonePayload(t *testing.T) {
	repoRoot, runDir := setupRollbackFixtureRepo(t)

	// validateToolFactRefs (internal/investigations) drops refs that do not
	// resolve on disk, so the stub must point at a real artifact.
	factPath := filepath.Join(runDir, "02_tool_facts", "trustir", "fact.json")
	if err := os.MkdirAll(filepath.Dir(factPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(factPath, []byte(`{"status":"success"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	roundOne, err := json.Marshal(map[string]any{
		"thought": "asking the fact layer first",
		"actions": []map[string]any{{
			"name": "fact_layer_query",
			"args": map[string]any{"operation": "cpp.state.rollback_version_propagation"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The done payload reports NO tool_fact_refs — exactly what the real run
	// emitted.
	roundTwo := roundResponseWithDone(t, map[string]any{
		"summary":    "version propagation reviewed",
		"candidates": []map[string]any{},
		"investigations": []map[string]any{{
			"twe_ids": []string{"TWE-STATE-001"},
			"filled_roles": map[string]any{
				"claim_producer": map[string]any{"path": "core/crypto/signed_hdr.c", "start_line": 1, "symbol": "shdr_load_pub_key"},
			},
			"tool_fact_refs": []string{},
		}},
	})

	registry := actions.NewDefaultRegistryWithNav()
	registry.Register(stubFactLayerQuery{ref: factPath})

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-toolfactref",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{RepoURL: "https://github.com/OP-TEE/optee_os", Commit: "43ed01d2"},
		Client:   &mockLLM{scripts: []string{string(roundOne), roundTwo}},
		Registry: registry,
		Budget:   defaultTestBudget(),
	})
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Investigations) != 1 {
		t.Fatalf("Investigations len = %d, want 1", len(result.Investigations))
	}

	refs := result.Investigations[0].ToolFactRefs
	if len(refs) != 1 || refs[0] != factPath {
		t.Fatalf("ToolFactRefs = %v, want [%s] — the planner executed the query itself, "+
			"so the ref must not be lost when the model omits it", refs, factPath)
	}

	// And it must reach the Case Pack, which is what the downstream agents read.
	if len(result.CasePacks) != 1 {
		t.Fatalf("CasePacks len = %d, want 1", len(result.CasePacks))
	}
	packRefs := result.CasePacks[0].ToolFactRefs
	if len(packRefs) != 1 || packRefs[0] != factPath {
		t.Errorf("CasePack.ToolFactRefs = %v, want [%s]", packRefs, factPath)
	}
}

// A ref the model DID report must not be duplicated when the planner adds
// what it executed.
func TestPlannerRun_ModelReportedToolFactRefIsNotDuplicated(t *testing.T) {
	repoRoot, runDir := setupRollbackFixtureRepo(t)

	factPath := filepath.Join(runDir, "02_tool_facts", "trustir", "fact.json")
	if err := os.MkdirAll(filepath.Dir(factPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(factPath, []byte(`{"status":"success"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	roundOne, err := json.Marshal(map[string]any{
		"thought": "asking the fact layer first",
		"actions": []map[string]any{{
			"name": "fact_layer_query",
			"args": map[string]any{"operation": "cpp.state.rollback_version_propagation"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	roundTwo := roundResponseWithDone(t, map[string]any{
		"summary":    "version propagation reviewed",
		"candidates": []map[string]any{},
		"investigations": []map[string]any{{
			"twe_ids": []string{"TWE-STATE-001"},
			"filled_roles": map[string]any{
				"claim_producer": map[string]any{"path": "core/crypto/signed_hdr.c", "start_line": 1, "symbol": "shdr_load_pub_key"},
			},
			"tool_fact_refs": []string{factPath},
		}},
	})

	registry := actions.NewDefaultRegistryWithNav()
	registry.Register(stubFactLayerQuery{ref: factPath})

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-toolfactref-dedup",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{RepoURL: "https://github.com/OP-TEE/optee_os", Commit: "43ed01d2"},
		Client:   &mockLLM{scripts: []string{string(roundOne), roundTwo}},
		Registry: registry,
		Budget:   defaultTestBudget(),
	})
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Investigations) != 1 {
		t.Fatalf("Investigations len = %d, want 1", len(result.Investigations))
	}
	if refs := result.Investigations[0].ToolFactRefs; len(refs) != 1 {
		t.Fatalf("ToolFactRefs = %v, want exactly one entry (no duplicate)", refs)
	}
}

// A ToolFact this loop did not execute must NOT reach the investigation.
//
// The pipeline used to prefetch the fact-layer queries the run's invariants
// called for and union the refs into every investigation the Planner
// reported — so a lead the model reached on its own still shipped evidence
// the old invariant had selected, and nothing downstream could tell the two
// apart. §6 requires a lead's reasons to reference facts the Planner has
// seen; a fact collected on its behalf is not one of them.
func TestPlannerRun_AFactTheLoopDidNotExecuteDoesNotReachTheInvestigation(t *testing.T) {
	repoRoot, runDir := setupRollbackFixtureRepo(t)

	factPath := filepath.Join(runDir, "02_tool_facts", "trustir", "prefetched.json")
	if err := os.MkdirAll(filepath.Dir(factPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(factPath, []byte(`{"status":"success"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// The model never calls fact_layer_query and reports no refs.
	done := roundResponseWithDone(t, map[string]any{
		"summary":    "no fact layer call this round",
		"candidates": []map[string]any{},
		"investigations": []map[string]any{{
			"twe_ids": []string{"TWE-STATE-001"},
			"filled_roles": map[string]any{
				"claim_producer": map[string]any{"path": "core/crypto/signed_hdr.c", "start_line": 1, "symbol": "shdr_load_pub_key"},
			},
			"tool_fact_refs": []string{},
		}},
	})

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-no-prefetch",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{RepoURL: "https://github.com/OP-TEE/optee_os", Commit: "a9386bf"},
		Client:   &mockLLM{scripts: []string{done}},
		Registry: actions.NewDefaultRegistryWithNav(),
		Budget:   defaultTestBudget(),
	})
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Investigations) != 1 {
		t.Fatalf("Investigations len = %d", len(result.Investigations))
	}
	if refs := result.Investigations[0].ToolFactRefs; len(refs) != 0 {
		t.Errorf("ToolFactRefs = %v, want none — this loop executed no fact-layer query", refs)
	}
}
