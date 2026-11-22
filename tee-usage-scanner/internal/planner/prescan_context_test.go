package planner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm/llmtest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

func prescanPlannerFixture(t *testing.T) (RunConfig, artifacts.ToolFact, *PlannerState, ObservationSet, *ReconState) {
	t.Helper()
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "input.c"), []byte("int entry(int n) { return n; }\nint consume(int n) { return n; }\nint unrelated(void) { return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "revision", root)
	if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "prescan-run", RepoURL: "fixture", Commit: "revision", LocalPath: root, Scope: scope}); err != nil {
		t.Fatal(err)
	}
	tree, err := sourcehash.TreeExcluding(root, []string{run})
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(map[string]any{"query_version": "teecheck.cpp.entry_taint.v1", "query_sha256": strings.Repeat("c", 64), "tree_content_sha256": tree, "total_paths": 1, "ranked_candidates": []any{map[string]int{"path_index": 0}}})
	fact := artifacts.ToolFact{SchemaVersion: artifacts.SchemaVersionToolFactV1, RequestID: "prescan-request", FactID: "taint-prescan-" + strings.Repeat("a", 64), ArgumentsSHA256: strings.Repeat("a", 64), Tool: "codeql-cpp-entry-taint", Operation: artifacts.TaintPrescanOperation, RepoCommit: scope.Commit, Scope: &scope, Status: "success", Result: result,
		Locations: []artifacts.ToolLocation{},
		Paths:     [][]artifacts.ToolPathStep{{{Kind: "source", Location: artifacts.ToolLocation{Path: "input.c", StartLine: 1, EndLine: 1, Symbol: "entry"}, Message: "n"}, {Kind: "sink", Location: artifacts.ToolLocation{Path: "input.c", StartLine: 2, EndLine: 2, Symbol: "consume"}, Message: "n"}}}, CoverageGaps: []string{"Static may-flow is not a vulnerability verdict."}}
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	path := runfs.TrustIRToolFactPath(run, fact.FactID)
	if err := runfs.WriteJSON(path, fact); err != nil {
		t.Fatal(err)
	}
	cfg := RunConfig{RunID: "prescan-run", SampleIndex: 2, RunDir: run, RepoRoot: root, Profile: PromptProfile{RepoURL: "fixture", Commit: "revision"}, Budget: NewDefaultBudget(), Registry: actions.NewDefaultRegistryWithNav(), PreScannedTaint: &PreScannedTaint{FactRef: path, ContentSHA256: fact.ContentSHA256, Summary: preScannedTaintHeading + "\n\n#1 | fact_ref=" + path + " | entry (input.c:1) -> consume (input.c:2)\n", CoverageGaps: fact.CoverageGaps}}
	state := NewState(cfg.RunID)
	ref := "obs:2:1:0:read"
	state.Rounds = []artifacts.RoundRecord{{Round: 1, Actions: []artifacts.RoundAction{{Name: "read_file", Args: json.RawMessage(`{"path":"input.c","start":1,"end":3}`)}}, Observations: []artifacts.RoundObservation{{Name: "read_file", OK: true, Ref: ref, ActionIndex: 0, Output: "1: int entry(int n) { return n; }\n2: int consume(int n) { return n; }\n3: int unrelated(void) { return 0; }\n"}}}}
	observed := ObservationSet{}
	observed.Record(ref, true)
	var executed []string
	seedPreScannedTaint(cfg.PreScannedTaint, &fact, &observed, &executed)
	recon := NewReconState(ReconModeIndexed).WithTotals(3, 6, 3)
	recon.ObserveAction("read_file", state.Rounds[0].Actions[0].Args, true)
	return cfg, fact, state, observed, recon
}

func TestPrescanLeadOpensAfterSourceWithoutClaimingBroadCoverage(t *testing.T) {
	cfg, _, state, observed, recon := prescanPlannerFixture(t)
	if recon.AllowLead() || recon.Satisfied() {
		t.Fatal("fixture accidentally satisfied broad reconnaissance")
	}
	payload := OpenAuditLeadPayload{SecurityQuestion: "Does the source value satisfy the consumer's bounds contract?", TargetSymbolIDs: []artifacts.SymbolID{"input.c::entry"}, Reason: []string{"The presented path links the observed entry and consumer."}, ReasonFactRefs: []string{cfg.PreScannedTaint.FactRef}}
	lead, res := openLead(cfg, recon, observed, leadArgs(t, payload), 2, state)
	if !res.OK || lead.LeadID == "" {
		t.Fatalf("source-grounded prescan lead refused: %+v", res)
	}
	if recon.Satisfied() {
		t.Fatal("targeted source read incorrectly claimed broad coverage")
	}
	state.AuditLeads = append(state.AuditLeads, lead)
	update := updateLead(cfg, state, observed, []string{cfg.PreScannedTaint.FactRef}, leadArgs(t, map[string]any{"lead_id": lead.LeadID, "add_taint_fact_refs": []string{cfg.PreScannedTaint.FactRef}}), 3)
	if !update.OK || len(state.AuditLeads[0].TaintFactRefs) != 1 || state.AuditLeads[0].State != artifacts.LeadStateExpanded {
		t.Fatalf("prescan evidence did not expand lead: %+v", update)
	}
	contract := artifacts.CaseInvariantV2{Subjects: []artifacts.ContractSubject{{Path: "input.c", Symbol: "entry"}}, Preconditions: []string{"the entry receives a value"}, RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "the consumer's bounds requirement is enforced"}, SecurityEffect: "bounds-sensitive use"}
	formalized := formalizeContract(cfg, state, observed, []string{cfg.PreScannedTaint.FactRef}, artifacts.RoundRecord{}, leadArgs(t, map[string]any{"lead_id": lead.LeadID, "contract": contract}))
	if !formalized.OK || len(state.Contracts) != 1 {
		t.Fatalf("prescan-backed contract refused: %+v", formalized)
	}
	found := false
	for _, ref := range state.Contracts[0].EvidenceRefs {
		if ref.Kind == "tool_fact" && ref.Ref == cfg.PreScannedTaint.FactRef && ref.ContentSHA256 != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("bound contract lost immutable prescan evidence")
	}
	contract.EvidenceRefs = []artifacts.ContractEvidenceRef{{Kind: "observation", Ref: cfg.PreScannedTaint.FactRef}}
	mislabelled := formalizeContract(cfg, state, observed, []string{cfg.PreScannedTaint.FactRef}, artifacts.RoundRecord{}, leadArgs(t, map[string]any{"lead_id": lead.LeadID, "contract": contract}))
	if mislabelled.OK {
		t.Fatal("prescan ToolFact was accepted as a source observation")
	}
}

func TestPrescanLeadRequiresPresentedEndpointSource(t *testing.T) {
	for _, mode := range []string{"no source", "cards only", "entry only", "current round only", "unrelated target", "forged ref"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _, state, observed, recon := prescanPlannerFixture(t)
			payload := OpenAuditLeadPayload{SecurityQuestion: "Does the flow meet its bounds contract?", TargetSymbolIDs: []artifacts.SymbolID{"input.c::entry"}, Reason: []string{"Investigate the presented flow."}, ReasonFactRefs: []string{cfg.PreScannedTaint.FactRef}}
			switch mode {
			case "no source", "current round only":
				state.Rounds = nil
			case "cards only":
				state.Rounds[0].Actions[0].Name = "get_function_card"
				state.Rounds[0].Observations[0].Name = "get_function_card"
			case "entry only":
				state.Rounds[0].Observations[0].Output = "1: int entry(int n) { return n; }\n"
			case "unrelated target":
				payload.TargetSymbolIDs = []artifacts.SymbolID{"input.c::unrelated"}
			case "forged ref":
				payload.ReasonFactRefs = []string{"taint-prescan-forged"}
			}
			if _, res := openLead(cfg, recon, observed, leadArgs(t, payload), 2, state); res.OK {
				t.Fatal("unread or unsupported prescan lead accepted")
			}
		})
	}
}

func TestPrescanContextRejectsTamperAndForeignFacts(t *testing.T) {
	for _, mode := range []string{"content", "scope", "other run", "missing digest", "unsupported status", "changed source"} {
		t.Run(mode, func(t *testing.T) {
			cfg, fact, _, _, _ := prescanPlannerFixture(t)
			switch mode {
			case "content":
				fact.Paths[0][0].Message = "changed"
			case "scope":
				fact.Scope.RepoURL = "different"
				fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
			case "other run":
				cfg.RunDir = t.TempDir()
			case "missing digest":
				fact.ContentSHA256 = ""
			case "unsupported status":
				fact.Status = "unresolved"
				fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
			case "changed source":
				if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "input.c"), []byte("int changed;\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := runfs.WriteJSON(cfg.PreScannedTaint.FactRef, fact); err != nil {
				t.Fatal(err)
			}
			if _, _, err := validatePreScannedTaint(cfg); err == nil {
				t.Fatal("invalid prescan accepted")
			}
		})
	}
}

func TestPrescanFirstRoundAndCompletedResumeValidateImmutableEvidence(t *testing.T) {
	cfg, fact, _, _, _ := prescanPlannerFixture(t)
	client := &llmtest.FakeClient{Default: `{"actions":[{"name":"done","args":{"summary":"no conclusion","candidates":[]}}]}`}
	cfg.Client = client
	cfg.Budget.MaxReconRounds = 0
	result := Run(context.Background(), cfg)
	if result.Err != nil || len(client.Calls) == 0 {
		t.Fatalf("planner setup: %v", result.Err)
	}
	if !strings.Contains(client.Calls[0].Messages[0].Content, preScannedTaintHeading) || !strings.Contains(client.Calls[0].Messages[0].Content, cfg.PreScannedTaint.FactRef) {
		t.Fatal("first round did not receive prescan clues")
	}
	fact.Paths[0][0].Message = "tampered and rehashed"
	fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
	if err := runfs.WriteJSON(cfg.PreScannedTaint.FactRef, fact); err != nil {
		t.Fatal(err)
	}
	cfg.Resume = true
	cfg.Client = &llmtest.FakeClient{Default: client.Default}
	if got := Run(context.Background(), cfg); got.Err == nil {
		t.Fatal("completed checkpoint bypassed prescan immutability validation")
	}
}

func TestPrescanPromptBoundAndNoSourceReadCredit(t *testing.T) {
	cfg, fact, _, _, recon := prescanPlannerFixture(t)
	state := NewState(cfg.RunID)
	state.PreScannedTaint = cfg.PreScannedTaint
	state.PreScannedTaint.Summary = strings.Repeat("#candidate entry -> sink\n\n", 2000)
	block := preScannedTaintBlock(state.PreScannedTaint)
	if len(block) > preScannedTaintMaxBytes || !strings.Contains(block, "not verdicts") {
		t.Fatalf("invalid bounded preview size=%d", len(block))
	}
	observed := ObservationSet{}
	var executed []string
	beforeFiles, beforeSymbols := recon.DistinctFilesRead(), recon.DistinctSymbolsViewed()
	seedPreScannedTaint(cfg.PreScannedTaint, &fact, &observed, &executed)
	if !observed.Observed(cfg.PreScannedTaint.FactRef) || len(executed) != 1 || recon.DistinctFilesRead() != beforeFiles || recon.DistinctSymbolsViewed() != beforeSymbols {
		t.Fatal("presenting prescan changed source-read coverage")
	}
	state.Rounds = []artifacts.RoundRecord{{Round: 1}}
	if prompt := BuildRoundPrompt(state, cfg.Profile, cfg.Budget, nil); strings.Contains(prompt, preScannedTaintHeading) {
		t.Fatal("full prescan preview repeated beyond first round")
	}
}

func TestPrescanNearLimitPreviewRetainsFirstCandidate(t *testing.T) {
	context := &PreScannedTaint{FactRef: "02_tool_facts/trustir/taint-prescan-valid.json"}
	var summary strings.Builder
	summary.WriteString(preScannedTaintHeading + "\n\n")
	summary.WriteString("#1 | entry (core/entry.c:10) -> sink (core/copy.c:20)\n\n")
	for summary.Len() < preScannedTaintMaxBytes-100 {
		summary.WriteString("#next | " + strings.Repeat("path ", 50) + "\n\n")
	}
	context.Summary = summary.String()
	block := preScannedTaintBlock(context)
	if len(block) > preScannedTaintMaxBytes || !strings.Contains(block, "#1 | entry") {
		t.Fatalf("bounded preview dropped all ranked candidates: bytes=%d", len(block))
	}
}

func TestPrescanDoesNotConstrainAnOtherwiseObservedBroadLead(t *testing.T) {
	cfg, _, state, observed, recon := prescanPlannerFixture(t)
	recon.SkipReconnaissance()
	recon.Observe("get_function_card", "input.c::unrelated", true)
	payload := OpenAuditLeadPayload{SecurityQuestion: "Does this observed adjacent function satisfy its caller's requirement?", TargetSymbolIDs: []artifacts.SymbolID{"input.c::unrelated"}, Reason: []string{"A related clue motivates source review of the observed adjacent function."}, ReasonFactRefs: []string{cfg.PreScannedTaint.FactRef}}
	if _, res := openLead(cfg, recon, observed, leadArgs(t, payload), 2, state); !res.OK {
		t.Fatalf("prescan introduced a new restriction on ordinary lead creation: %+v", res)
	}
}

func TestPrescanIsNotAutomaticallyAttachedToUnrelatedInvestigations(t *testing.T) {
	cfg, _, state, _, _ := prescanPlannerFixture(t)
	raw := []map[string]any{{"twe_ids": []string{"TWE-FLOW-001"}, "filled_roles": map[string]any{"source": map[string]any{"path": "input.c", "start_line": 3, "symbol": "unrelated"}}, "tool_fact_refs": []string{}}}
	investigations, _, _ := processInvestigations(raw, cfg, state, []string{cfg.PreScannedTaint.FactRef})
	if len(investigations) != 1 || len(investigations[0].ToolFactRefs) != 0 {
		t.Fatalf("prefetched batch clues were attached as unrelated case evidence: %+v", investigations)
	}
}

func TestPrescanLeadMatchesSignedAndNamespacedFunctionNames(t *testing.T) {
	for _, target := range []string{"input.c::ns::entry", "cpp:input.c:1:ns::entry(int)", "input.c::other::entry"} {
		t.Run(target, func(t *testing.T) {
			cfg, fact, state, observed, recon := prescanPlannerFixture(t)
			code := "namespace ns { int entry(int n) { return n; } }\nint consume(int n) { return n; }\nint unrelated(void) { return 0; }\n"
			if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "input.c"), []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
			tree, err := sourcehash.TreeExcluding(cfg.RepoRoot, []string{cfg.RunDir})
			if err != nil {
				t.Fatal(err)
			}
			var identity map[string]any
			if err = json.Unmarshal(fact.Result, &identity); err != nil {
				t.Fatal(err)
			}
			identity["tree_content_sha256"] = tree
			fact.Result, _ = json.Marshal(identity)
			fact.Paths[0][0].Location.Symbol = "ns::entry(int)"
			fact.ContentSHA256 = artifacts.ToolFactContentSHA256(fact)
			cfg.PreScannedTaint.ContentSHA256 = fact.ContentSHA256
			if err = runfs.WriteJSON(cfg.PreScannedTaint.FactRef, fact); err != nil {
				t.Fatal(err)
			}
			state.Rounds[0].Observations[0].Output = "1: namespace ns { int entry(int n) { return n; } }\n2: int consume(int n) { return n; }\n3: int unrelated(void) { return 0; }\n"
			payload := OpenAuditLeadPayload{SecurityQuestion: "Does this entry enforce the consumer's bound?", TargetSymbolIDs: []artifacts.SymbolID{artifacts.SymbolID(target)}, Reason: []string{"The source and sink have been read."}, ReasonFactRefs: []string{cfg.PreScannedTaint.FactRef}}
			_, res := openLead(cfg, recon, observed, leadArgs(t, payload), 2, state)
			want := target != "input.c::other::entry"
			if res.OK != want {
				t.Fatalf("accepted=%v want=%v: %s", res.OK, want, res.Error)
			}
		})
	}
}
