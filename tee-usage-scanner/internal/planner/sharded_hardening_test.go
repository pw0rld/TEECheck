package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/sourcehash"
)

func setupTriageRepoFixture(t *testing.T, funcCount int) (string, string, RunConfig) {
	t.Helper()
	root := t.TempDir()
	run := t.TempDir()
	coreDir := filepath.Join(root, "core", "tee")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create multiple core entry files so bounded stratified triage produces >= 2 batches (12 funcs/batch).
	for i := 0; i < funcCount; i++ {
		fileIdx := i % 4
		rel := fmt.Sprintf("core/tee/svc_%d.c", fileIdx)
		full := filepath.Join(root, filepath.FromSlash(rel))
		fn := fmt.Sprintf("int syscall_op_%02d(int x) {\n    if (x < 0) return -1;\n    return x;\n}\n\n", i)
		f, err := os.OpenFile(full, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(fn); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}
	scope := runfs.BuildScope("fixture-triage", "rev1", root)
	if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "triage-resume-test",
		RepoURL:       "fixture-triage",
		LocalPath:     root,
		Commit:        "rev1",
		Scope:         scope,
		Focus:         "tee",
	}); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		SchemaVersion: artifacts.SchemaVersionProjectMapV1,
		RunID:         "triage-resume-test",
		Scope:         scope,
		Repository:    artifacts.RepositoryCard{FileCount: 4},
		Capabilities:  artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := RunConfig{
		RunID:              "triage-resume-test",
		RepoRoot:           root,
		RunDir:             run,
		Registry:           actions.NewDefaultRegistryWithNav(),
		Budget:             NewDefaultBudget(),
		StrictContractExit: true,
		Workers:            2,
		Model:              "strong-model",
		ScoutModel:         "fast-model",
	}
	return root, run, cfg
}

func TestShardedRoundAllocationHonorsPhaseLimits(t *testing.T) {
	sc := &shardedCoordinator{budget: Budget{MaxRounds: 1, MaxReconRounds: 2}}
	if sc.allocRound(true) != 1 || sc.allocRound(true) != 2 || sc.allocRound(true) != 0 {
		t.Fatal("reconnaissance exceeded its configured round allowance")
	}
	if sc.allocRound(false) != 3 || sc.allocRound(false) != 0 {
		t.Fatal("investigation exceeded its configured round allowance")
	}
	if sc.budget.RoundsUsed != 3 || sc.budget.ReconRoundsUsed != 2 {
		t.Fatalf("rejected rounds spent budget: %+v", sc.budget)
	}
}

func TestEntryTriageScheduleReservesDefaultScoutRounds(t *testing.T) {
	budget := NewDefaultBudget()
	previous := map[int]TriageBatchRecord{
		0: {Status: "succeeded"},
		1: {Status: "failed"},
		2: {Status: "succeeded"},
	}
	got := planEntryTriageBatches(budget, 4, 16, previous)
	want := map[int]bool{1: true, 3: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default triage must preserve eight Scout rounds and reuse succeeded batches: got %v, want %v", got, want)
	}
	if budget.ReconRoundsUsed != 0 || budget.RoundsUsed != 0 {
		t.Fatalf("planning consumed rounds before dispatch: %+v", budget)
	}
	if got := planEntryTriageBatches(budget, 0, 16, previous); len(got) != budget.MaxReconRounds {
		t.Fatalf("without Scouts triage should use the remaining round allowance: %v", got)
	}
	budget.ReconRoundsUsed = budget.MaxReconRounds - 1
	if got := planEntryTriageBatches(budget, 1, 16, previous); len(got) != 0 {
		t.Fatalf("triage borrowed the final reserved Scout round: %v", got)
	}
}

func TestShardedCheckpointKeepsStableStateAndPendingWork(t *testing.T) {
	_, run, cfg := setupShardedFixture(t)
	cfg.Budget.Start()
	tree, err := sourcehash.TreeExcluding(cfg.RepoRoot, []string{run})
	if err != nil {
		t.Fatal(err)
	}
	sc := &shardedCoordinator{
		cfg: cfg, state: NewState(cfg.RunID), recon: NewReconState(ReconModeIndexed),
		budget: cfg.Budget, loopStartedAt: time.Now(), observedPaths: map[string]bool{},
		completedScouts: map[string]bool{"dispatch_tables": true}, completedLeads: map[string]bool{},
		checkpointEnabled: true, treeHash: tree, binaryHash: "fixture",
		scoutProposals: []scoutLeadProposal{{Bucket: "dispatch_tables", Question: "retained proposal", CanonArgs: json.RawMessage(`{}`)}},
	}
	if err := sc.saveCheckpointLocked(false, "", nil); err != nil {
		t.Fatal(err)
	}
	_, reserved, ok := sc.reserveShardTokens(20, true, false, 1000, 256)
	if !ok {
		t.Fatal("fixture cannot reserve request tokens")
	}
	sc.state.AuditLeads = append(sc.state.AuditLeads, artifacts.AuditLead{LeadID: "uncommitted"})
	sc.mutatingRounds = map[int]bool{1: true}
	sc.budget.ConsumePhaseTokens(42, false)
	if err := sc.saveCheckpointLocked(false, "", nil); err != nil {
		t.Fatal(err)
	}
	var cp Checkpoint
	if err := runfs.ReadJSON(CheckpointPath(run), &cp); err != nil {
		t.Fatal(err)
	}
	if len(cp.State.AuditLeads) != 0 || len(cp.Sharded.ScoutProposals) != 1 || cp.Sharded.ScoutProposals[0].Question != "retained proposal" {
		t.Fatalf("checkpoint mixed an unfinished round or lost pending scout work: %+v", cp)
	}
	if cp.Budget.TokensUsed != 42 || cp.Sharded.ReservedRecon != reserved || cp.Sharded.ReservedInvest != 0 {
		t.Fatalf("checkpoint lost spent or in-flight request budget: %+v %+v", cp.Budget, cp.Sharded)
	}
}

func TestEntryTriagePersistFailureRetainsStableCheckpointObservations(t *testing.T) {
	_, run, cfg := setupTriageRepoFixture(t, entryTriageMinFunctions)
	cfg.Events = events.Nop{}
	cfg.Budget.Start()
	cfg.ScoutClient = funcLLMClient{fn: func(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
		return llm.GenerateResponse{Text: `{"candidates":[]}`, Usage: llm.Usage{PromptTokens: 20, CompletionTokens: 10, TotalTokens: 30}}, nil
	}}
	tree, err := sourcehash.TreeExcluding(cfg.RepoRoot, []string{run})
	if err != nil {
		t.Fatal(err)
	}
	sc := &shardedCoordinator{
		cfg: cfg, state: NewState(cfg.RunID), recon: NewReconState(ReconModeTreeOnly),
		budget: cfg.Budget, loopStartedAt: time.Now(), observedPaths: map[string]bool{},
		completedScouts: map[string]bool{}, completedLeads: map[string]bool{},
		checkpointEnabled: true, treeHash: tree, binaryHash: "fixture", roundsLog: runfs.RoundsLogPath(run),
	}
	if err := sc.saveCheckpointLocked(false, "", nil); err != nil {
		t.Fatal(err)
	}
	// Block the real round append only after a valid initial checkpoint exists.
	if err := os.MkdirAll(sc.roundsLog, 0o700); err != nil {
		t.Fatal(err)
	}
	_, succeeded := sc.runEntryTriage(context.Background(), artifacts.BoundaryTopology{}, 1)
	if succeeded || len(sc.observations.ok) == 0 || len(sc.mutatingRounds) == 0 || len(sc.state.Rounds) != 0 {
		t.Fatalf("fixture did not fail after recording source observations: succeeded=%v observations=%d mutating=%d rounds=%d",
			succeeded, len(sc.observations.ok), len(sc.mutatingRounds), len(sc.state.Rounds))
	}
	if sc.triageBatches[0].Reason != "persist_error" {
		t.Fatalf("unexpected failure: %+v", sc.triageBatches)
	}
	var cp Checkpoint
	if err := runfs.ReadJSON(CheckpointPath(run), &cp); err != nil {
		t.Fatal(err)
	}
	if len(cp.State.Rounds) != 0 || len(cp.Observations) != 0 || len(cp.ObservedPaths) != 0 || len(cp.ObservedFileHashes) != 0 || len(cp.Recon.FilesRead) != 0 {
		t.Fatalf("uncommitted triage source observations entered the checkpoint: %+v", cp)
	}
	if cp.Budget.TokensUsed != 30 {
		t.Fatalf("stable checkpoint lost the failed round's spent budget: %+v", cp.Budget)
	}
}

func TestRunShardedCannotCompleteWithoutAssignedSourceRead(t *testing.T) {
	_, run, cfg := setupShardedFixture(t)
	cfg.Client = funcLLMClient{fn: func(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
		return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"no inspection"}}]}`}, nil
	}}
	cfg.ScoutClient = cfg.Client
	result := RunSharded(context.Background(), cfg)
	if result.Bundle.PlannerMeta.TerminationReason == "sharded_done" {
		t.Fatal("scouts that never inspected source were recorded as complete")
	}
	var cp Checkpoint
	if err := runfs.ReadJSON(CheckpointPath(run), &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Completed || cp.CachedResult != nil || len(cp.Sharded.CompletedScouts) > 1 {
		t.Fatalf("uninspected boundary scouts were cached as completed: %+v", cp.Sharded)
	}
}

func TestRunShardedPreservesExplicitZeroScoutTemperature(t *testing.T) {
	_, _, cfg := setupShardedFixture(t)
	cfg.Temperature = 0.8
	cfg.ScoutTemperature = 0
	temperatures := make(chan float64, 32)
	cfg.ScoutClient = funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
		temperatures <- req.Temperature
		return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"empty"}}]}`}, nil
	}}
	cfg.Client = cfg.ScoutClient
	RunSharded(context.Background(), cfg)
	close(temperatures)
	if len(temperatures) == 0 {
		t.Fatal("scout fixture dispatched no requests")
	}
	for temperature := range temperatures {
		if temperature != 0 {
			t.Fatalf("explicit scout zero was replaced by planner temperature: %v", temperature)
		}
	}
}

// Regression 1: Triage records per-batch succeeded/failed/unrun status, incomplete
// checkpoint never blocks --resume, and --resume reuses succeeded batches while
// retrying failed batches.
func TestRunSharded_TriageBatchFailureResumeReusesSucceededAndCompletes(t *testing.T) {
	_, run, cfg := setupTriageRepoFixture(t, 14) // 2 batches (12 + 2)

	var mu sync.Mutex
	batchCalls := map[int]int{}
	failBatch2 := true

	triageClient := funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
		msg := req.Messages[0].Content
		if strings.Contains(msg, "ENTRY TRIAGE BATCH 1/2") {
			mu.Lock()
			batchCalls[1]++
			mu.Unlock()
			resp := `{"candidates":[{"file":"core/tee/svc_0.c","symbol":"syscall_op_00","start_line":1,"end_line":4,"severity":"high","security_question":"Does syscall_op_00 validate upper bound on x?","reason":["Line 2 checks x < 0 but not upper bound"],"related_twes":["TWE-FLOW-001"]}]}`
			return llm.GenerateResponse{Text: resp, Usage: llm.Usage{PromptTokens: 120, CompletionTokens: 40, TotalTokens: 160}}, nil
		}
		if strings.Contains(msg, "ENTRY TRIAGE BATCH 2/2") {
			mu.Lock()
			batchCalls[2]++
			shouldFail := failBatch2
			mu.Unlock()
			if shouldFail {
				return llm.GenerateResponse{Text: `NOT VALID JSON {{{`, Usage: llm.Usage{PromptTokens: 80, CompletionTokens: 10, TotalTokens: 90}}, nil
			}
			return llm.GenerateResponse{Text: `{"candidates":[]}`, Usage: llm.Usage{PromptTokens: 80, CompletionTokens: 10, TotalTokens: 90}}, nil
		}
		return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"ok"}}]}`, Usage: llm.Usage{PromptTokens: 40, CompletionTokens: 10, TotalTokens: 50}}, nil
	}}

	invClient := funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
		msg := req.Messages[0].Content
		leadMatch := regexp.MustCompile(`ISOLATED LEAD INVESTIGATION \((lead-s0-\d+)`).FindStringSubmatch(msg)
		refMatch := regexp.MustCompile(`reason_fact_refs: \[(\S+)\]`).FindStringSubmatch(msg)
		b, _ := json.Marshal(map[string]any{"actions": []any{
			map[string]any{"name": "close_lead", "args": map[string]any{
				"lead_id":   leadMatch[1],
				"reason":    "Verified benign in fixture",
				"fact_refs": []string{refMatch[1]},
			}},
			map[string]any{"name": "done", "args": map[string]any{"summary": "closed"}},
		}})
		return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 80, CompletionTokens: 20, TotalTokens: 100}}, nil
	}}

	cfg.ScoutClient = triageClient
	cfg.Client = invClient

	// Pass 1: Batch 2 returns invalid JSON -> incomplete run, checkpoint MUST NOT be Completed/Cached.
	res1 := RunSharded(context.Background(), cfg)
	if res1.Err != nil {
		t.Fatalf("unexpected fatal error on pass 1: %v", res1.Err)
	}
	if res1.Bundle.PlannerMeta.TerminationReason != "sharded_incomplete" {
		t.Fatalf("pass 1 TerminationReason = %q, want sharded_incomplete", res1.Bundle.PlannerMeta.TerminationReason)
	}

	cp1, err := InspectCheckpoint(run, cfg.RepoRoot)
	if err != nil {
		t.Fatalf("InspectCheckpoint pass 1 failed: %v", err)
	}
	if cp1.Completed || cp1.CachedResult != nil {
		t.Fatalf("incomplete pass 1 checkpoint must not be Completed or CachedResult: completed=%v cached=%v", cp1.Completed, cp1.CachedResult != nil)
	}
	if cp1.Sharded == nil || cp1.Sharded.TriageSummary == nil {
		t.Fatalf("expected TriageSummary in checkpoint")
	}
	ts1 := cp1.Sharded.TriageSummary
	if ts1.CandidateTotal != 14 || ts1.SelectedTotal != 14 || ts1.SucceededBatches != 1 || ts1.FailedBatches != 1 || ts1.FailureReasons["invalid_json"] != 1 {
		t.Fatalf("unexpected pass 1 TriageSummary: %+v", ts1)
	}
	if !strings.Contains(ts1.OrderingDisclosure, "OP-TEE") {
		t.Fatalf("expected OP-TEE ordering disclosure, got %q", ts1.OrderingDisclosure)
	}
	// Verify triage persisted real round observations and audit_leads.jsonl with canonical full obs ref.
	leadsData, err := os.ReadFile(runfs.AuditLeadsPath(run))
	if err != nil || !strings.Contains(string(leadsData), "obs:0:") {
		t.Fatalf("expected triage lead persisted in audit_leads.jsonl with canonical obs ref, err=%v data=%q", err, string(leadsData))
	}
	roundsData, err := os.ReadFile(runfs.RoundsLogPath(run))
	if err != nil || !strings.Contains(string(roundsData), "syscall_op_00") {
		t.Fatalf("expected triage source snippet persisted in rounds.jsonl, err=%v", err)
	}

	// Pass 2: Resume with Batch 2 fixed -> Batch 1 MUST be reused (call count stays 1), Batch 2 retried (call count = 2).
	mu.Lock()
	failBatch2 = false
	mu.Unlock()
	cfg.Resume = true
	res2 := RunSharded(context.Background(), cfg)
	if res2.Err != nil {
		t.Fatalf("resumed pass 2 failed: %v", res2.Err)
	}
	if res2.Bundle.PlannerMeta.TerminationReason != "sharded_done" {
		t.Fatalf("pass 2 TerminationReason = %q, want sharded_done", res2.Bundle.PlannerMeta.TerminationReason)
	}
	mu.Lock()
	c1, c2 := batchCalls[1], batchCalls[2]
	mu.Unlock()
	if c1 != 1 {
		t.Fatalf("expected batch 1 to be reused on resume (calls=1), got %d", c1)
	}
	if c2 != 2 {
		t.Fatalf("expected batch 2 to be retried on resume (calls=2), got %d", c2)
	}
	cp2, err := InspectCheckpoint(run, cfg.RepoRoot)
	if err != nil {
		t.Fatalf("InspectCheckpoint pass 2 failed: %v", err)
	}
	if !cp2.Completed || cp2.CachedResult == nil {
		t.Fatalf("completed pass 2 checkpoint must be Completed with CachedResult")
	}
	var diskSummary TriageSummary
	if err := runfs.ReadJSON(filepath.Join(runfs.PlannerDir(run), "triage_summary.json"), &diskSummary); err != nil {
		t.Fatalf("read triage_summary.json: %v", err)
	}
	if diskSummary.SucceededBatches != 2 || diskSummary.FailedBatches != 0 || diskSummary.UnrunBatches != 0 {
		t.Fatalf("unexpected final triage_summary.json: %+v", diskSummary)
	}
}

// Regression 2: Short obs:<sample>:<round>:<idx> refs are accepted only when
// uniquely matched, canonicalized to full obs:<sample>:<round>:<idx>:<hash>
// before persisting into leads or contracts, and pass offline contracts.Validate.
func TestShortObsRef_CanonicalizedToContractAndOfflineValidated(t *testing.T) {
	root, run, cfg := setupShardedFixture(t)
	state := NewState(cfg.RunID)
	recon := NewReconState(ReconModeIndexed)
	recon.SkipReconnaissance()
	rfArgs, _ := json.Marshal(map[string]any{"path": "a.c", "start": 1, "end": 4})
	recon.ObserveSourceOutput("read_file", rfArgs, "1: int entry_a(int x) { return x > 0; }\n", true)

	fullRef := MakeObservationRef(cfg.RunID, 0, 1, 0, "sha256:aaa111")
	shortRef := "obs:0:1:0"
	ambigA := MakeObservationRef(cfg.RunID, 0, 2, 0, "sha256:bbb111")
	ambigB := MakeObservationRef(cfg.RunID, 0, 2, 0, "sha256:ccc222")
	ambigShort := "obs:0:2:0"

	var obs ObservationSet
	obs.Record(fullRef, true)
	obs.Record(ambigA, true)
	obs.Record(ambigB, true)

	// Ambiguous short ref must be rejected.
	if _, ok := obs.Resolve(ambigShort); ok {
		t.Fatalf("expected ambiguous short ref %q to be rejected", ambigShort)
	}
	// Unique short ref resolves to full canonical ref.
	if got, ok := obs.Resolve(shortRef); !ok || got != fullRef {
		t.Fatalf("Resolve(%q) = (%q, %v), want (%q, true)", shortRef, got, ok, fullRef)
	}

	// Open lead with short ref -> persisted lead must store full canonical ref.
	openArgs, _ := json.Marshal(OpenAuditLeadPayload{
		SecurityQuestion: "Does entry_a reject negative x?",
		TargetSymbolIDs:  []artifacts.SymbolID{"cpp:a.c:1:entry_a(int)"},
		Reason:           []string{"Observed entry_a"},
		ReasonFactRefs:   []string{shortRef},
		Uncertainty:      "medium",
	})
	lead, res := openLead(cfg, recon, obs, openArgs, 1, state)
	if !res.OK {
		t.Fatalf("openLead failed: %s", res.Error)
	}
	if len(lead.ReasonFactRefs) != 1 || lead.ReasonFactRefs[0] != fullRef {
		t.Fatalf("expected canonical full ref %q in lead, got %v", fullRef, lead.ReasonFactRefs)
	}
	state.AuditLeads = append(state.AuditLeads, lead)

	// Update lead with short ref -> note FactRef must store full canonical ref.
	updArgs, _ := json.Marshal(map[string]any{
		"lead_id": lead.LeadID,
		"add_notes": []map[string]any{
			{"fact_ref": shortRef, "summary": "Confirmed entry_a lacks upper bound"},
		},
	})
	if ures := updateLead(cfg, state, obs, nil, updArgs, 2); !ures.OK {
		t.Fatalf("updateLead failed: %s", ures.Error)
	}
	if state.AuditLeads[0].EvidenceNotes[0].FactRef != fullRef {
		t.Fatalf("expected canonical full ref %q in updateLead note, got %q", fullRef, state.AuditLeads[0].EvidenceNotes[0].FactRef)
	}

	// Formalize contract passing short observation ref -> persisted contract JSON must contain full canonical ref
	// and pass offline contracts.Validate.
	roundRec := artifacts.RoundRecord{
		Round: 1,
		Actions: []artifacts.RoundAction{
			{Name: "read_file", Args: rfArgs},
		},
		Observations: []artifacts.RoundObservation{
			{Name: "read_file", OK: true, Ref: fullRef, Output: "1: int entry_a(int x) { return x > 0; }\n"},
		},
	}
	if err := state.AppendRoundAndPersist(roundRec, runfs.RoundsLogPath(run)); err != nil {
		t.Fatal(err)
	}
	fcArgs, _ := json.Marshal(map[string]any{
		"lead_id": lead.LeadID,
		"contract": artifacts.CaseInvariantV2{
			LeadRef:          lead.LeadID,
			Subjects:         []artifacts.ContractSubject{{Path: "a.c", Symbol: "entry_a"}},
			Preconditions:    []string{"entry_a receives untrusted x"},
			RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "entry_a rejects negative x"},
			SecurityEffect:   "input acceptance",
			EvidenceRefs:     []artifacts.ContractEvidenceRef{{Kind: "observation", Ref: shortRef}},
		},
	})
	fres := formalizeContract(cfg, state, obs, nil, roundRec, fcArgs)
	if !fres.OK {
		t.Fatalf("formalizeContract failed: %s", fres.Error)
	}

	// Load persisted contract from disk and verify canonical ref + offline contracts.Validate.
	contractFiles, err := filepath.Glob(filepath.Join(runfs.PlannerDir(run), "contracts", "*.json"))
	if err != nil || len(contractFiles) != 1 {
		t.Fatalf("expected 1 persisted contract file, got %v (err=%v)", contractFiles, err)
	}
	var persisted artifacts.CaseInvariantV2
	if err := runfs.ReadJSON(contractFiles[0], &persisted); err != nil {
		t.Fatal(err)
	}
	foundFull := false
	for _, er := range persisted.EvidenceRefs {
		if er.Kind == "observation" {
			if er.Ref == shortRef {
				t.Fatalf("persisted contract still contains short obs ref %q", shortRef)
			}
			if er.Ref == fullRef {
				foundFull = true
			}
		}
	}
	if !foundFull {
		t.Fatalf("expected persisted contract to contain canonical full ref %q, got %+v", fullRef, persisted.EvidenceRefs)
	}
	manifest, err := runfs.LoadManifest(run)
	if err != nil {
		t.Fatal(err)
	}
	binding := contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: manifest.Scope}
	if err := contracts.Validate(persisted, binding); err != nil {
		t.Fatalf("offline contracts.Validate failed on persisted contract: %v", err)
	}
}

// Regression 3: Changing worker count or artificially inverting per-shard response
// latencies MUST select the exact same ordered investigation leads.
func TestRunSharded_DeterministicLeadSelectionAcrossWorkersAndLatencies(t *testing.T) {
	runOnce := func(workers int, invertLatency bool) []string {
		_, run, cfg := setupShardedFixture(t)
		cfg.Workers = workers

		var mu sync.Mutex
		scoutStep := map[string]int{}
		cfg.ScoutClient = funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
			msg := req.Messages[0].Content
			bucket := "dispatch_tables"
			file := "a.c"
			sym := "cpp:a.c:1:entry_a(int)"
			if strings.Contains(msg, "bucket=struct_bridges") {
				bucket = "struct_bridges"
				file = "b.c"
				sym = "cpp:b.c:1:entry_b(int)"
			}
			if invertLatency && bucket == "dispatch_tables" {
				time.Sleep(40 * time.Millisecond)
			} else if !invertLatency && bucket == "struct_bridges" {
				time.Sleep(40 * time.Millisecond)
			}
			mu.Lock()
			scoutStep[bucket]++
			step := scoutStep[bucket]
			mu.Unlock()
			if step == 1 {
				b, _ := json.Marshal(map[string]any{"actions": []any{
					map[string]any{"name": "read_file", "args": map[string]any{"path": file, "start": 1, "end": 4}},
				}})
				return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 60, CompletionTokens: 20, TotalTokens: 80}}, nil
			}
			refMatch := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(msg)
			b, _ := json.Marshal(map[string]any{"actions": []any{
				map[string]any{"name": "open_audit_lead", "args": map[string]any{
					"security_question": "Does " + file + " validate input?",
					"target_symbol_ids": []string{sym},
					"reason":            []string{"Read " + file},
					"reason_fact_refs":  []string{refMatch[1]},
				}},
				map[string]any{"name": "done", "args": map[string]any{"summary": "done"}},
			}})
			return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 60, CompletionTokens: 20, TotalTokens: 80}}, nil
		}}

		cfg.Client = funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
			msg := req.Messages[0].Content
			leadMatch := regexp.MustCompile(`ISOLATED LEAD INVESTIGATION \((lead-s0-\d+)`).FindStringSubmatch(msg)
			refMatch := regexp.MustCompile(`reason_fact_refs: \[(\S+)\]`).FindStringSubmatch(msg)
			b, _ := json.Marshal(map[string]any{"actions": []any{
				map[string]any{"name": "close_lead", "args": map[string]any{
					"lead_id":   leadMatch[1],
					"reason":    "checked",
					"fact_refs": []string{refMatch[1]},
				}},
				map[string]any{"name": "done", "args": map[string]any{"summary": "done"}},
			}})
			return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 60, CompletionTokens: 20, TotalTokens: 80}}, nil
		}}

		res := RunSharded(context.Background(), cfg)
		if res.Err != nil {
			t.Fatalf("RunSharded(workers=%d, invert=%v) failed: %v", workers, invertLatency, res.Err)
		}
		cp, err := InspectCheckpoint(run, cfg.RepoRoot)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, l := range cp.Leads {
			out = append(out, fmt.Sprintf("%s|%v|%s", l.LeadID, l.TargetSymbolIDs, l.SecurityQuestion))
		}
		return out
	}

	seq := runOnce(1, false)
	parInverted := runOnce(4, true)
	if len(seq) != 2 || !reflect.DeepEqual(seq, parInverted) {
		t.Fatalf("lead selection was non-deterministic:\n  workers=1: %v\n  workers=4 (inverted): %v", seq, parInverted)
	}
}

// Regression 4: Atomic token reservation prevents concurrent workers from
// overshooting the token budget, and settles/releases reserved tokens on timeout
// or failure paths so subsequent calls can proceed.
func TestRunSharded_AtomicTokenReservationEnforcesCapAndSettlesOnFailure(t *testing.T) {
	_, _, cfg := setupShardedFixture(t)
	cfg.Events = events.Nop{}
	cfg.Budget = NewDefaultBudget()
	cfg.Budget.MaxTokens = 2400
	cfg.Budget.MaxReconTokens = 2400
	cfg.Budget.ConvergenceReserveTokens = 0
	cfg.Budget.Start()

	sc := &shardedCoordinator{
		cfg:             cfg,
		state:           NewState(cfg.RunID),
		budget:          cfg.Budget,
		loopStartedAt:   time.Now(),
		observedPaths:   map[string]bool{},
		completedScouts: map[string]bool{},
		completedLeads:  map[string]bool{},
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var callNum atomic.Int32
	client := funcLLMClient{fn: func(_ context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
		n := callNum.Add(1)
		if n == 1 {
			close(started)
			<-release
			return llm.GenerateResponse{}, context.DeadlineExceeded
		}
		return llm.GenerateResponse{
			Text:  `{"ok":true}`,
			Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
		}, nil
	}}

	var wg sync.WaitGroup
	var err1 error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _, err1 = sc.askShardLLM(context.Background(), client, "fast-model", 0.2, 2000, "worker-1", 1, true, false, "sys", "user")
	}()

	<-started
	// While worker-1 holds its ~2000+ token reservation against a 3000-token cap,
	// worker-2 MUST be rejected atomically with errReplyBudget (cannot overshoot).
	_, _, _, err2 := sc.askShardLLM(context.Background(), client, "fast-model", 0.2, 2000, "worker-2", 2, true, false, "sys", "user")
	if !errors.Is(err2, errReplyBudget) {
		close(release)
		wg.Wait()
		t.Fatalf("expected concurrent worker-2 to hit errReplyBudget while reservation held, got %v", err2)
	}

	// Let worker-1 time out; its reservation MUST be released cleanly.
	close(release)
	wg.Wait()
	if !errors.Is(err1, context.DeadlineExceeded) {
		t.Fatalf("expected worker-1 deadline exceeded, got %v", err1)
	}
	sc.mu.Lock()
	resTot, resRecon := sc.reservedTotal, sc.reservedRecon
	sc.mu.Unlock()
	if resTot != 0 || resRecon != 0 {
		t.Fatalf("expected reservations to settle back to 0 after failure, got total=%d recon=%d", resTot, resRecon)
	}

	// Now worker-3 MUST succeed and settle actual usage (150 tokens).
	_, inTok, outTok, err3 := sc.askShardLLM(context.Background(), client, "fast-model", 0.2, 2000, "worker-3", 3, true, false, "sys", "user")
	if err3 != nil || inTok+outTok != 150 {
		t.Fatalf("expected worker-3 to succeed after settlement, err=%v tokens=%d", err3, inTok+outTok)
	}
	sc.mu.Lock()
	used := sc.budget.TokensUsed
	sc.mu.Unlock()
	if used != 150 {
		t.Fatalf("expected TokensUsed=150 after settlement, got %d", used)
	}
}
