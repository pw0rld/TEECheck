package planner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
)

// roundResponseWithDone builds one round's raw LLM response text: a single
// `done` action whose args are exactly doneArgs (marshaled, not
// hand-written — a transcription slip in a hand-written JSON literal is a
// notoriously easy way to end up testing "the LLM sent malformed JSON"
// instead of the intended scenario).
func roundResponseWithDone(t *testing.T, doneArgs map[string]any) string {
	t.Helper()
	resp := map[string]any{
		"thought": "reporting the investigation",
		"actions": []map[string]any{{"name": "done", "args": doneArgs}},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestPlannerRun_RollbackInvestigation_Vulnerable is §24's core acceptance
// scenario driven end to end through planner.Run with a scripted LLM (no
// real model, no real CodeQL — the LLM's `done` payload stands in for what
// a real model would report after using fact_layer_query/read_file/
// reverse_trace across several rounds): the investigation locates
// shdr_load_pub_key (claim_producer) but the version is never propagated
// into the runtime key struct — rollback_authority is missing, so the
// attack chain is not demonstrated end to end.
func TestPlannerRun_RollbackInvestigation_Vulnerable(t *testing.T) {
	repoRoot, runDir := setupRollbackFixtureRepo(t)
	catalogPath := writeEmptySinkCatalog(t)

	roundResp := roundResponseWithDone(t, map[string]any{
		"summary":    "subkey_version is parsed but never written into key->version",
		"candidates": []map[string]any{},
		"investigations": []map[string]any{{
			"twe_ids":           []string{"TWE-STATE-001"},
			"invariant_ids":     []string{"INV-STATE-001"},
			"architecture_refs": []string{"comp:ta-loader"},
			"filled_roles": map[string]any{
				"claim_producer": map[string]any{"path": "core/crypto/signed_hdr.c", "start_line": 262, "symbol": "shdr_load_pub_key"},
			},
			"missing_roles":     []string{"version_propagated_to_authority"},
			"required_evidence": []string{"freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input"},
			"tool_fact_refs":    []string{},
		}},
	})
	client := &mockLLM{scripts: []string{roundResp}}

	arch := &artifacts.ArchitectureModel{
		Components: []artifacts.ArchitectureElement{{ID: "comp:ta-loader", Kind: "component", Name: "TA loader", State: artifacts.EvidenceObserved}},
	}
	invariants := []artifacts.ProjectInvariant{{
		InvariantID: "INV-STATE-001",
		Statement:   "subkey_version must propagate to check_update_version before a TA is accepted",
		RelatedTWEs: []string{"TWE-STATE-001"},
	}}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:        "test-rollback-vuln",
		RepoRoot:     repoRoot,
		RunDir:       runDir,
		Profile:      planner.PromptProfile{RepoURL: "https://github.com/OP-TEE/optee_os", Commit: "a9386bf9"},
		Client:       client,
		Registry:     actions.NewDefaultRegistryWithSinks(catalogPath),
		Budget:       defaultTestBudget(),
		Architecture: arch,
		Invariants:   invariants,
		TWEPlaybooks: map[string]planner.TWEPlaybookSummary{
			"TWE-STATE-001": {
				CommonDefenses:       []string{"correctly_propagated_signed_version_to_rollback_database"},
				CommonFalsePositives: []string{"restored_state_is_only_a_non_security_cache"},
			},
		},
	})

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Investigations) != 1 {
		t.Fatalf("Investigations len = %d, want 1", len(result.Investigations))
	}
	inv := result.Investigations[0]

	if inv.Classification != "standard" {
		t.Errorf("Classification = %q, want standard", inv.Classification)
	}
	if _, ok := inv.FilledRoles["claim_producer"]; !ok {
		t.Errorf("FilledRoles = %+v, want claim_producer (a real file was named)", inv.FilledRoles)
	}
	if len(inv.MissingRoles) != 1 || inv.MissingRoles[0] != "version_propagated_to_authority" {
		t.Errorf("MissingRoles = %v, want [version_propagated_to_authority]", inv.MissingRoles)
	}
	if len(inv.ArchitectureRefs) != 1 || inv.ArchitectureRefs[0] != "comp:ta-loader" {
		t.Errorf("ArchitectureRefs = %v, want [comp:ta-loader] (grounded against the supplied ArchitectureModel)", inv.ArchitectureRefs)
	}
	if len(inv.InvariantIDs) != 1 || inv.InvariantIDs[0] != "INV-STATE-001" {
		t.Errorf("InvariantIDs = %v, want [INV-STATE-001] (grounded against the supplied invariants)", inv.InvariantIDs)
	}

	// §24 acceptance: the Planner must not conclude "confirmed" merely
	// because a role is missing. artifacts.TWEInvestigation has no verdict
	// field, so there is structurally nothing that COULD carry such a
	// conclusion — this is enforced by the type, not by a runtime check.
	// What we can check is that the gap is recorded as an open task.
	joined := strings.Join(inv.CoverageGaps, " | ")
	if !strings.Contains(joined, "version_propagated_to_authority") {
		t.Errorf("CoverageGaps = %v, want the missing role reflected", inv.CoverageGaps)
	}

	if len(result.CasePacks) != 1 {
		t.Fatalf("CasePacks len = %d, want 1", len(result.CasePacks))
	}
	pack := result.CasePacks[0]
	if len(pack.CommonDefenses) != 1 || len(pack.CommonFalsePositives) != 1 {
		t.Errorf("CasePack playbook context not carried: defenses=%v fps=%v", pack.CommonDefenses, pack.CommonFalsePositives)
	}
	if len(pack.MissingLinks) != 1 {
		t.Errorf("CasePack.MissingLinks = %v, want one entry for the missing role", pack.MissingLinks)
	}

	// The investigation must be persisted as a schema-valid artifact
	// (Persist itself schema-validates — see internal/investigations) —
	// checking the file exists on disk proves the planner actually wrote
	// it, not just built it in memory.
	invPath := filepath.Join(runDir, "03_investigations", inv.InvestigationID+".json")
	if _, err := os.Stat(invPath); err != nil {
		t.Errorf("expected investigation persisted at %s: %v", invPath, err)
	}
}

// TestPlannerRun_RollbackInvestigation_Fixed mirrors the vulnerable case but
// with the version-propagation role filled too — §24's "在 fixed variant 中
// 识别版本传播或对应保护": every role is located, so the attack chain the
// playbook describes is structurally complete. This is NOT the same as the
// Planner asserting "safe" — investigations carry no verdict field at all.
func TestPlannerRun_RollbackInvestigation_Fixed(t *testing.T) {
	repoRoot, runDir := setupRollbackFixtureRepo(t)
	catalogPath := writeEmptySinkCatalog(t)

	roundResp := roundResponseWithDone(t, map[string]any{
		"summary":    "subkey_version is now propagated into key->version",
		"candidates": []map[string]any{},
		"investigations": []map[string]any{{
			"twe_ids": []string{"TWE-STATE-001"},
			"filled_roles": map[string]any{
				"claim_producer":                  map[string]any{"path": "core/crypto/signed_hdr.c", "start_line": 262, "symbol": "shdr_load_pub_key"},
				"version_propagated_to_authority": map[string]any{"path": "core/crypto/signed_hdr.c", "start_line": 320},
			},
		}},
	})
	client := &mockLLM{scripts: []string{roundResp}}

	result := planner.Run(context.Background(), planner.RunConfig{
		RunID:    "test-rollback-fixed",
		RepoRoot: repoRoot,
		RunDir:   runDir,
		Profile:  planner.PromptProfile{RepoURL: "https://github.com/OP-TEE/optee_os", Commit: "43ed01d2"},
		Client:   client,
		Registry: actions.NewDefaultRegistryWithSinks(catalogPath),
		Budget:   defaultTestBudget(),
	})

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Investigations) != 1 {
		t.Fatalf("Investigations len = %d, want 1", len(result.Investigations))
	}
	inv := result.Investigations[0]
	if len(inv.MissingRoles) != 0 {
		t.Errorf("MissingRoles = %v, want none — both roles were located with real file evidence", inv.MissingRoles)
	}
	for _, gap := range inv.CoverageGaps {
		if strings.Contains(gap, "attack chain incomplete") {
			t.Errorf("CoverageGaps unexpectedly still incomplete: %v", inv.CoverageGaps)
		}
	}
}

func setupRollbackFixtureRepo(t *testing.T) (repoRoot, runDir string) {
	t.Helper()
	repoRoot = t.TempDir()
	runDir = t.TempDir()
	writeRepoFile(t, repoRoot, "core/crypto/signed_hdr.c",
		"TEE_Result shdr_load_pub_key(void) {\n// ...\nkey->version = subkey->subkey_version;\n}\n")
	return repoRoot, runDir
}

func writeEmptySinkCatalog(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cpp.json")
	catalog := `{"schema_version":"teecheck.sink_catalog.v2","language":"cpp","groups":[]}`
	if err := os.WriteFile(path, []byte(catalog), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
