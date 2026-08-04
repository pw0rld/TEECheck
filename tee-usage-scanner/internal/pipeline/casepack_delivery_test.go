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

// The two investigations in donePassWithInvestigation resolve to the same
// file and so collapse into one Case Pack. Their required_evidence differs so
// that a collapse which keeps only one side's fields is detectable on disk.
const (
	evidenceFromFirstInvestigation  = "freshness_value_is_never_propagated_from_load_or_provisioning_into_the_guards_input"
	evidenceFromSecondInvestigation = "the_rollback_guard_never_reads_the_propagated_freshness_value"

	// The traced attack path is carried by the first investigation and the
	// counter-evidence by the second, so the pack on disk can only hold
	// both if the collapse preserves the primary's ordered flow AND unions
	// the loser's counter-evidence.
	flowStepFromFirstInvestigation         = "signed version read here and never propagated"
	counterEvidenceFromSecondInvestigation = "the_caller_revalidates_the_version_before_the_guard_runs"
)

// donePassWithInvestigation builds one planner round response whose single
// `done` action reports BOTH halves of the done payload: one
// done.investigations entry for TWE-STATE-001 and two candidates. It is the
// counterpart to l3planner_test.go's donePass, which always sends an empty
// investigations list and so never exercises the CasePack-from-investigation
// path this test targets — and, until 2026-07-28, the two files between them
// left the combined case uncovered: this file drove investigations with zero
// candidates, l3planner_test.go drove candidates with zero investigations,
// and nothing ran the rich/thin interaction inside runL3Planner. Both
// CRITICALs found in the final branch review lived in exactly that gap.
//
// filled_roles names src/a.c (created by setupPlannerRun) with symbol "f",
// which really appears in that fixture's content ("int f(void) {...}") —
// Validate's anti-hallucination check (internal/investigations/validate.go)
// would otherwise demote the role to missing, and a pack with no TargetFiles
// is dropped by planner.Merge's targetKey (empty key), never reaching disk.
//
// The candidates are deliberately one of each kind:
//
//   - src/a.c — the SAME file the investigation resolved to, so the thin
//     pack is absorbed into the rich one. This is the path that silently
//     emptied every playbook field when absorb took its fields from
//     whichever pack happened to be positionally first.
//   - src/b.c — a different file, so its thin pack survives on its own and
//     the run really does deliver both halves to disk.
//
// Candidate paths must exist in the fixture repo: planner.Run's
// convertCandidates drops hallucinated paths before packs are built.
func donePassWithInvestigation(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"thought": "done",
		"actions": []map[string]any{{
			"name": "done",
			"args": map[string]any{
				"summary": "s",
				"candidates": []map[string]any{
					{"id": "cand-a", "kind": "state_machine", "priority": "high", "paths": []string{"src/a.c"}, "why_selected": []string{"same file as the investigation"}},
					{"id": "cand-b", "kind": "attestation", "priority": "low", "paths": []string{"src/b.c"}, "why_selected": []string{"candidate-only file"}},
				},
				"investigations": []map[string]any{{
					"twe_ids":           []string{"TWE-STATE-001"},
					"required_evidence": []string{evidenceFromFirstInvestigation},
					"filled_roles": map[string]any{
						"claim_producer": map[string]any{"path": "src/a.c", "start_line": 1, "symbol": "f"},
					},
					// The attack path this investigation traced: until
					// 2026-07-28 it existed only in
					// 03_investigations/<id>.json, a file no production
					// reader opens, so it never reached an agent.
					"observed_flow": []map[string]any{{
						"location": map[string]any{"path": "src/a.c", "start_line": 1, "symbol": "f"},
						"kind":     "source",
						"message":  flowStepFromFirstInvestigation,
					}},
				}, {
					// A SECOND investigation resolving to the same file: two
					// TWE scenarios about one function, which is routine on
					// the 1-4 file benchmark fixtures and reachable at the
					// default --samples 1. Merge keeps both (it only folds
					// thin into rich) and DedupePacks then collapses them,
					// so this entry is what carries the rich+rich collapse
					// through the real pipeline. Its required_evidence is
					// distinct from the first's precisely so a collapse that
					// keeps only one side is visible on disk.
					"twe_ids":           []string{"TWE-STATE-001"},
					"required_evidence": []string{evidenceFromSecondInvestigation},
					"filled_roles": map[string]any{
						"rollback_authority": map[string]any{"path": "src/a.c", "start_line": 1, "symbol": "f"},
					},
					// Counter-evidence on the SECOND investigation, which
					// loses the identity slot in the collapse: it reaches
					// disk only if absorb unions the field rather than
					// keeping the primary's.
					"counterevidence": []string{counterEvidenceFromSecondInvestigation},
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
	repoRoot, runDir := setupPlannerRun(t, "src/a.c", "src/b.c")
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
	if err := runL3Planner(cfg, client, nil, repoRoot, runDir, events.Nop{}, nil, nil); err != nil {
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
	// Two: the investigation's pack (with the src/a.c candidate absorbed
	// into it) and the src/b.c candidate's own pack.
	if len(paths) != 2 {
		t.Fatalf("downstream glob sees %d packs, want 2 (one per target file)", len(paths))
	}

	byTargetFile := map[string]artifacts.CasePack{}
	for _, p := range paths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(p, &pack); err != nil {
			t.Fatal(err)
		}
		for _, f := range pack.TargetFiles {
			byTargetFile[f] = pack
		}
	}

	// The rich half: the playbook knowledge must reach disk even though a
	// candidate naming the same file was folded into this pack.
	got, ok := byTargetFile["src/a.c"]
	if !ok {
		t.Fatalf("no pack targets src/a.c; got %v", byTargetFile)
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
	// Both investigations collapsed into this pack, so BOTH evidence
	// checklists must be on it. Keeping only the first side's is the
	// PR-06 data loss with a different mechanism: knowledge produced and
	// then discarded before any agent could read it.
	for _, want := range []string{evidenceFromFirstInvestigation, evidenceFromSecondInvestigation} {
		found := false
		for _, ev := range got.RequiredEvidence {
			if ev == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required_evidence = %v, missing %q — a collapse of two investigations "+
				"on the same file must union their knowledge, not pick one", got.RequiredEvidence, want)
		}
	}

	// The attack path and the counter-evidence must reach the same
	// case-*.json every agent globs. Before 2026-07-28 both were built,
	// validated and persisted to 03_investigations/<id>.json — and stopped
	// there, because BuildCasePack carried eleven fields and not these two.
	if len(got.ObservedFlow) != 1 || got.ObservedFlow[0].Message != flowStepFromFirstInvestigation {
		t.Errorf("observed_flow = %+v, want the traced step from the first investigation — "+
			"the attack path is stranded in 03_investigations/ again", got.ObservedFlow)
	}
	foundCounter := false
	for _, c := range got.CounterEvidence {
		if c == counterEvidenceFromSecondInvestigation {
			foundCounter = true
		}
	}
	if !foundCounter {
		t.Errorf("counterevidence = %v, missing %q — evidence against the case must survive the "+
			"collapse the same way required_evidence does", got.CounterEvidence, counterEvidenceFromSecondInvestigation)
	}

	// ...and the candidate it absorbed contributed its why_selected and its
	// higher priority rather than replacing the pack wholesale.
	if len(got.WhySelected) == 0 {
		t.Error("the absorbed candidate's why_selected must reach disk too")
	}
	if got.Priority != "high" {
		t.Errorf("priority = %q, want the absorbed candidate's higher %q", got.Priority, "high")
	}

	// The thin half: a candidate on a file no investigation touched still
	// becomes its own reviewable case.
	other, ok := byTargetFile["src/b.c"]
	if !ok {
		t.Fatalf("no pack targets src/b.c; the candidate half of the done payload was lost, got %v", byTargetFile)
	}
	if len(other.CommonDefenses) != 0 || len(other.RelatedTWEs) != 0 {
		t.Errorf("a candidate-only pack must not inherit another pack's playbook knowledge: %+v", other)
	}
}
