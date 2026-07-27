package pipeline

// The 2026-07-27 defect in one test: the Planner produced the richest Case
// Pack in every run — the sole carrier of a TWE playbook's common_defenses
// and common_false_positives (§24) — and no downstream consumer could see
// it, because it was written as 03_cases/<investigation_id>.json while
// every consumer globs case-*.json. The assertion that let that live for
// four days was len(result.CasePacks) == 1: it proved the pack was
// constructed, never that it was readable.
//
// This test asserts from the CONSUMER side, through the REAL persistence
// path (runL3Planner, not planner.Merge/planner.Write called directly —
// persistence moved out of planner.Run in the C1 fix and now happens once,
// after the --samples loop, in runL3Planner; see l3planner_test.go's header
// comment and internal/pipeline/run.go). A future reader must not
// "simplify" this back into an in-memory result.CasePacks assertion: that
// is exactly the shape of check that shipped the original defect, because
// it never traverses the filename Write actually chooses or the glob
// consumers actually use.
//
// Consumers of the case-*.json glob this test defends (keep in sync):
// internal/expert/run.go, internal/challenger/run.go, internal/verifier/run.go,
// internal/arbiter/run.go, internal/pipeline/run.go, internal/stats/.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// rollbackPlaybookYAML is a minimal, schema-valid teecheck.twe_playbook.v1
// playbook for TWE-STATE-001 (see internal/twecontext.Playbook.Validate and
// knowledge/twe/playbooks/rollback.yml for the real, larger version this
// mirrors). It exists purely so runL3Planner's twecontext.Load call (in
// internal/pipeline/run.go) has a catalog to build TWEPlaybookSummary.
// CommonDefenses/CommonFalsePositives from — the exact fields the
// investigation -> CasePack path (internal/planner's processInvestigations,
// internal/investigations.BuildCasePack) is supposed to carry to disk.
const rollbackPlaybookYAML = `schema_version: teecheck.twe_playbook.v1
id: TWE-STATE-001
name: Trusted State Rollback
family: State
scenario: "An attacker restores stale trusted state whose freshness was never propagated to the enforcement point."
attacker_capabilities:
  - control_host_storage
look_for:
  - propagation_of_freshness_fields_to_rollback_guards
investigation_steps:
  - trace_version_or_epoch_fields_to_the_runtime_object
required_evidence:
  - freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input
common_defenses:
  - a_dominating_check_already_constrains_the_value
common_false_positives:
  - the_caller_validated_it_earlier
trustir_hints:
  - trace_restore_or_version_to_authority
`

// setupPlaybookKnowledgeRoot creates a knowledge root whose twe/playbooks/
// directory contains rollbackPlaybookYAML, matching the layout
// runL3Planner reads via filepath.Join(cfg.KnowledgeRoot, "twe", "playbooks").
func setupPlaybookKnowledgeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "twe", "playbooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rollback.yml"), []byte(rollbackPlaybookYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// donePassWithInvestigation builds one planner round response whose single
// `done` action reports no candidates but one done.investigations entry for
// TWE-STATE-001 — the counterpart to l3planner_test.go's donePass, which
// always sends an empty investigations list and so never exercises the
// CasePack-from-investigation path this test targets. filled_roles names
// src/a.c (created by setupPlannerRun) with symbol "f", which really
// appears in that fixture's content ("int f(void) {...}") — Validate's
// anti-hallucination check (internal/investigations/validate.go) would
// otherwise demote the role to missing, and a pack with no TargetFiles is
// dropped by planner.Merge's targetKey (empty key), never reaching disk.
func donePassWithInvestigation(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"thought": "done",
		"actions": []map[string]any{{
			"name": "done",
			"args": map[string]any{
				"summary":    "s",
				"candidates": []map[string]any{},
				"investigations": []map[string]any{{
					"twe_ids":           []string{"TWE-STATE-001"},
					"required_evidence": []string{"freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input"},
					"filled_roles": map[string]any{
						"claim_producer": map[string]any{"path": "src/a.c", "start_line": 1, "symbol": "f"},
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCasePacksReachDownstreamGlob(t *testing.T) {
	repoRoot, runDir := setupPlannerRun(t, "src/a.c")
	knowledgeRoot := setupPlaybookKnowledgeRoot(t)

	client := &llmtest.FakeClient{
		Responses: []string{donePassWithInvestigation(t)},
		Default:   donePassWithInvestigation(t),
	}

	cfg := config.Config{
		Focus:         "tee",
		RunDir:        runDir,
		KnowledgeRoot: knowledgeRoot,
		Samples:       1,
	}
	if err := runL3Planner(cfg, client, repoRoot, runDir, events.Nop{}, nil, nil); err != nil {
		t.Fatalf("runL3Planner: %v", err)
	}

	// Every stage that reads case packs (see the consumer list in this
	// file's header comment) uses exactly this glob — not a hardcoded
	// case-001.json. The glob pattern itself is the thing under test: the
	// 2026-07-27 defect wrote a filename this glob did not match, and every
	// downstream consumer silently saw zero packs.
	paths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(runDir), "case-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("downstream glob sees %d packs, want 1", len(paths))
	}

	var got artifacts.CasePack
	if err := runfs.ReadJSON(paths[0], &got); err != nil {
		t.Fatal(err)
	}
	for name, field := range map[string][]string{
		"related_twes":           got.RelatedTWEs,
		"required_evidence":      got.RequiredEvidence,
		"common_defenses":        got.CommonDefenses,
		"common_false_positives": got.CommonFalsePositives,
	} {
		if len(field) == 0 {
			t.Errorf("%s did not survive to the consumer's case-*.json glob — the playbook layer is disconnected again", name)
		}
	}
}
