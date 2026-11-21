package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type checkpointClient struct {
	calls    int
	failAt   int
	panicAt  int
	requests []llm.GenerateRequest
	done     bool
}

func (c *checkpointClient) Generate(_ context.Context, r llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	c.requests = append(c.requests, r)
	if c.panicAt == c.calls {
		panic("simulated process interruption")
	}
	if c.failAt == c.calls {
		return llm.GenerateResponse{}, fmt.Errorf("temporary connection loss")
	}
	body := `{"actions":[{"name":"read_file","args":{"path":"a.c"}}]}`
	if c.calls%2 == 0 {
		body = `{"actions":[{"name":"list_dir","args":{"path":"."}}]}`
	}
	if c.done {
		body = `{"actions":[{"name":"done","args":{"summary":"resumed","candidates":[]}}]}`
	}
	return llm.GenerateResponse{Text: body, Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
}
func checkpointConfig(t *testing.T, c llm.Client) RunConfig {
	t.Helper()
	root, run := reliabilityFixture(t)
	b := NewDefaultBudget()
	b.MaxReconRounds = 0
	b.MaxRounds = 10
	return RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Client: c, Registry: actions.NewDefaultRegistryWithNav(), Budget: b}
}
func interruptedRun(cfg RunConfig) { defer func() { _ = recover() }(); Run(context.Background(), cfg) }
func loadRawCheckpoint(t *testing.T, run string) *Checkpoint {
	t.Helper()
	data, err := os.ReadFile(CheckpointPath(run))
	if err != nil {
		t.Fatal(err)
	}
	var cp Checkpoint
	if err = json.Unmarshal(data, &cp); err != nil {
		t.Fatal(err)
	}
	cp.runDir = run
	return &cp
}
func TestCheckpointResumePreservesRoundsObservationsAndBudget(t *testing.T) {
	client := &checkpointClient{panicAt: 5}
	cfg := checkpointConfig(t, client)
	interruptedRun(cfg)
	cp, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastCommittedRound != 4 || len(cp.State.Rounds) != 4 || len(cp.Observations) != 4 || cp.Budget.RoundsUsed != 5 || cp.InFlight == nil {
		t.Fatalf("incomplete snapshot: %+v", cp)
	}
	if len(cp.ObservedFileHashes) != 1 || cp.ObservedFileHashes["a.c"] == "" {
		t.Fatalf("source observations missing: %+v", cp.ObservedFileHashes)
	}
	// A partial lead revision must not become accepted evidence after recovery.
	suffix := []byte(`{"run_id":"reliable","lead_id":"stale","state":"open"}` + "\n")
	f, err := os.OpenFile(filepath.Join(cfg.RunDir, "04_planner", "audit_leads.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(suffix)
	f.Close()
	if err = RestoreCheckpointJournals(cp); err != nil {
		t.Fatal(err)
	}
	stale, _ := os.ReadFile(filepath.Join(cfg.RunDir, "04_planner", "audit_leads.jsonl"))
	if len(stale) != 0 {
		t.Fatal("uncommitted lead survived")
	}
	cfg.Resume = true
	resumed := &checkpointClient{done: true}
	cfg.Client = resumed
	got := Run(context.Background(), cfg)
	if got.Err != nil {
		t.Fatal(got.Err)
	}
	if resumed.calls != 1 || got.Bundle.PlannerMeta.RoundsUsed != 6 {
		t.Fatalf("replayed completed round: calls=%d bundle=%+v", resumed.calls, got.Bundle)
	}
	if got.Bundle.PlannerMeta.TokensUsed <= 4*120+120 {
		t.Fatal("unknown in-flight usage was reset")
	}
	after, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Completed || len(after.State.Rounds) != 5 || len(after.Observations) < 4 || after.Loop.Action != "done" {
		t.Fatalf("restoration lost state: %+v", after)
	}
	cfg.Client = &checkpointClient{panicAt: 1}
	cached := Run(context.Background(), cfg)
	if cached.Err != nil || cached.Bundle.FinalSummary != "resumed" {
		t.Fatalf("completed result not cached: %+v", cached)
	}
}
func TestCheckpointRejectsChangedUnobservedSource(t *testing.T) {
	cfg := checkpointConfig(t, &checkpointClient{panicAt: 2})
	extra := filepath.Join(cfg.RepoRoot, "unobserved.c")
	os.WriteFile(extra, []byte("abc"), 0644)
	interruptedRun(cfg)
	os.WriteFile(extra, []byte("xyz"), 0644)
	before, _ := os.ReadFile(CheckpointPath(cfg.RunDir))
	if _, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot); err == nil || !strings.Contains(err.Error(), "source tree content changed") {
		t.Fatalf("unobserved change accepted: %v", err)
	}
	after, _ := os.ReadFile(CheckpointPath(cfg.RunDir))
	if string(before) != string(after) {
		t.Fatal("inspection mutated checkpoint")
	}
}
func TestCheckpointRejectsJournalPrefixTampering(t *testing.T) {
	cfg := checkpointConfig(t, &checkpointClient{panicAt: 2})
	interruptedRun(cfg)
	path := filepath.Join(cfg.RunDir, "04_planner", "rounds.jsonl")
	data, _ := os.ReadFile(path)
	data[0] = '!'
	os.WriteFile(path, data, 0644)
	if _, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot); err == nil || !strings.Contains(err.Error(), "journal prefix changed") {
		t.Fatalf("changed evidence accepted: %v", err)
	}
}
func TestCheckpointRestoresReconPrivateState(t *testing.T) {
	r := NewReconState(ReconModeIndexed).WithTotals(3, 9, 12)
	r.repositoryCardRead = true
	r.modulesViewed["core"] = true
	r.symbolsViewed["f"] = true
	r.symbolSpread["core"] = true
	r.filesRead["a.c"] = true
	r.linesRead["a.c"] = []lineRange{{2, 8}}
	r.entryCapability = "available"
	r.entrySurfaces = map[artifacts.SymbolID]artifacts.EntrySurface{}
	r.entryLinesRead = map[string]map[int]bool{"a.c": {2: true}}
	r.leadsOpened = 2
	r.phase = PhaseInvestigation
	r.budgetExhausted = true
	data, _ := json.Marshal(snapshotRecon(r))
	var snap reconSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	restored := snap.restore()
	if restored.phase != PhaseInvestigation || restored.leadsOpened != 2 || restored.linesRead["a.c"][0] != (lineRange{2, 8}) || !restored.entryLinesRead["a.c"][2] || !restored.modulesViewed["core"] {
		t.Fatalf("private recon state was lost: %+v", restored)
	}
}
func TestCheckpointBudgetElapsedDoesNotIncludeDowntime(t *testing.T) {
	cfg := checkpointConfig(t, &checkpointClient{panicAt: 2})
	interruptedRun(cfg)
	cp := loadRawCheckpoint(t, cfg.RunDir)
	cp.ElapsedNanos = int64(3 * time.Second)
	cp.InFlight = nil
	cp.Budget.TaintQueriesUsed = 3
	if err := writeCheckpoint(cp); err != nil {
		t.Fatal(err)
	}
	cfg.Resume = true
	cfg.Client = &checkpointClient{done: true}
	got := Run(context.Background(), cfg)
	if got.Err != nil {
		t.Fatal(got.Err)
	}
	if got.Bundle.PlannerMeta.WallClockMs < 3000 || got.Bundle.PlannerMeta.WallClockMs > 5000 || got.Bundle.PlannerMeta.TaintQueriesUsed != 3 {
		t.Fatalf("elapsed/quota not restored: %+v", got.Bundle.PlannerMeta)
	}
}
func TestCheckpointRespectsPolicyRefusalAndSampleIdentity(t *testing.T) {
	cfg := checkpointConfig(t, &checkpointClient{panicAt: 2})
	interruptedRun(cfg)
	cfg.Resume = true
	cfg.SampleIndex = 1
	got := Run(context.Background(), cfg)
	if got.Err == nil || !strings.Contains(got.Err.Error(), "another run, sample") {
		t.Fatal("cross-sample resume accepted")
	}
	cp := loadRawCheckpoint(t, cfg.RunDir)
	cp.TerminationReason = "policy_refusal"
	if err := writeCheckpoint(cp); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot); err == nil || !strings.Contains(err.Error(), "policy refusal") {
		t.Fatalf("policy rejection resumed: %v", err)
	}
}

type checkpointInterruptClient struct {
	client        llm.Client
	calls, stopAt int
}

func (c *checkpointInterruptClient) Generate(ctx context.Context, r llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	if c.calls == c.stopAt {
		panic("interrupted")
	}
	return c.client.Generate(ctx, r)
}
func TestCheckpointResumePreservesFormalizedLeadAndTaintEvidence(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.c"), []byte("int consume(int value) { return value; }\nint entry(int value) { return consume(value); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "revision", root)
	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "taint-integration", RepoURL: "fixture", Commit: "revision", LocalPath: root, Scope: scope, Focus: "tee"}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), manifest); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(run), artifacts.RepoFacts{RunID: manifest.RunID, Scope: scope, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable}, Symbols: []artifacts.Symbol{{SymbolID: "cpp:entry.c:2:entry(int)", Name: "entry", File: "entry.c", StartLine: 2, Signature: "(int)"}}}); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{RunID: manifest.RunID, Scope: scope, Repository: artifacts.RepositoryCard{FileCount: 1}, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable}}); err != nil {
		t.Fatal(err)
	}
	engine, db := &traceIntegrationEngine{}, &traceIntegrationDB{}
	client := &traceIntegrationClient{t: t}
	budget := NewDefaultBudget()
	budget.MaxReconRounds = 0
	budget.MaxTaintQueries = 1
	cfg := RunConfig{RunID: manifest.RunID, RepoRoot: root, RunDir: run, Profile: PromptProfile{RepoURL: manifest.RepoURL, Commit: manifest.Commit}, Client: &checkpointInterruptClient{client: client, stopAt: 5}, Registry: actions.NewDefaultRegistryWithFacts(engine, db, "", nil), Budget: budget}
	interruptedRun(cfg)
	cp, err := InspectCheckpoint(run, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.State.AuditLeads) != 1 || len(cp.State.Contracts) != 1 || len(cp.ExecutedToolFactRefs) == 0 || cp.Budget.TaintQueriesUsed != 1 {
		t.Fatalf("formalized evidence missing: %+v", cp)
	}
	cfg.Resume = true
	cfg.Client = client
	result := Run(context.Background(), cfg)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if engine.analyzeCalls != 1 || len(result.CasePacks) != 1 || len(result.CasePacks[0].CaseInvariants) != 1 {
		t.Fatalf("resume duplicated query or lost contract: analyze=%d result=%+v", engine.analyzeCalls, result)
	}
	invariant := result.CasePacks[0].CaseInvariants[0]
	found := false
	for _, ref := range invariant.EvidenceRefs {
		if ref.Kind == "tool_fact" && ref.Ref == client.factRef {
			found = true
		}
	}
	if !found || invariant.Grounding != "source_bound" {
		t.Fatalf("accepted taint binding lost: %+v", invariant)
	}
}

type heartbeatClient struct {
	started chan struct{}
	release chan struct{}
}

func (c *heartbeatClient) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	close(c.started)
	<-c.release
	return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"heartbeat","candidates":[]}}]}`, Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
}
func TestCheckpointHeartbeatRecordsBlockedActiveTime(t *testing.T) {
	c := &heartbeatClient{make(chan struct{}), make(chan struct{})}
	cfg := checkpointConfig(t, c)
	results := make(chan RunResult, 1)
	go func() { results <- Run(context.Background(), cfg) }()
	<-c.started
	defer func() {
		select {
		case <-c.release:
		default:
			close(c.release)
		}
	}()
	// Cross one heartbeat tick while Generate is blocked, then inspect the
	// atomic file concurrently with the running planner.
	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	cp, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot)
	close(c.release)
	result := <-results
	if err != nil {
		t.Fatal(err)
	}
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if cp.InFlight == nil || cp.ElapsedNanos < int64(time.Second) {
		t.Fatalf("active request time was not persisted: %+v", cp)
	}
}

type checkpointExitClient struct{ calls int }

func (c *checkpointExitClient) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	if c.calls == 3 {
		os.Exit(31)
	}
	return llm.GenerateResponse{Text: `{"actions":[{"name":"read_file","args":{"path":"a.c"}}]}`, Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
}
func TestCheckpointSurvivesProcessExit(t *testing.T) {
	if os.Getenv("TEECHECK_CHECKPOINT_EXIT_CHILD") == "1" {
		b := NewDefaultBudget()
		b.MaxReconRounds = 0
		b.MaxRounds = 10
		Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: os.Getenv("TEECHECK_CHECKPOINT_ROOT"), RunDir: os.Getenv("TEECHECK_CHECKPOINT_RUN"), Client: &checkpointExitClient{}, Registry: actions.NewDefaultRegistryWithNav(), Budget: b})
		os.Exit(32)
	}
	cfg := checkpointConfig(t, nil)
	command := exec.Command(os.Args[0], "-test.run=^TestCheckpointSurvivesProcessExit$")
	command.Env = append(os.Environ(), "TEECHECK_CHECKPOINT_EXIT_CHILD=1", "TEECHECK_CHECKPOINT_ROOT="+cfg.RepoRoot, "TEECHECK_CHECKPOINT_RUN="+cfg.RunDir)
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 31 {
		t.Fatalf("child did not exit at request: %v %s", err, output)
	}
	cp, err := InspectCheckpoint(cfg.RunDir, cfg.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastCommittedRound != 2 || cp.InFlight == nil || cp.Budget.RoundsUsed != 3 {
		t.Fatalf("crash lost checkpoint: %+v", cp)
	}
	cfg.Resume = true
	cfg.Client = &checkpointClient{done: true}
	result := Run(context.Background(), cfg)
	if result.Err != nil || result.Bundle.PlannerMeta.RoundsUsed != 4 {
		t.Fatalf("crash recovery failed: %+v", result)
	}
}
