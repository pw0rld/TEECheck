package planner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func setupShardedFixture(t *testing.T) (string, string, RunConfig) {
	t.Helper()
	root := t.TempDir()
	run := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte("int entry_a(int x) { return x > 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.c"), []byte("int entry_b(int y) { return y; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "rev1", root)
	if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{
		SchemaVersion: "teecheck.manifest.v1",
		RunID:         "sharded-test",
		RepoURL:       "fixture",
		LocalPath:     root,
		Commit:        "rev1",
		Scope:         scope,
		Focus:         "tee",
	}); err != nil {
		t.Fatal(err)
	}
	symA := artifacts.MakeSymbolID("cpp", "a.c", 1, "entry_a", "(int)")
	symB := artifacts.MakeSymbolID("cpp", "b.c", 1, "entry_b", "(int)")
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		SchemaVersion: artifacts.SchemaVersionProjectMapV1,
		RunID:         "sharded-test",
		Scope:         scope,
		Repository:    artifacts.RepositoryCard{FileCount: 2},
		Capabilities:  artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable, DirectCalls: artifacts.CapabilityAvailable, FieldAccesses: artifacts.CapabilityPartial, BuildReachability: artifacts.CapabilityUnavailable},
	}); err != nil {
		t.Fatal(err)
	}
	topo := artifacts.BoundaryTopology{
		SchemaVersion:   artifacts.SchemaVersionBoundaryTopologyV1,
		RunID:           "sharded-test",
		Scope:           scope,
		MaxClosureDepth: 3,
		EntryClosures: []artifacts.EntryClosure{
			{RootSymbolID: symA, RootName: "entry_a", RootPath: "a.c", RootModule: "modA", RootStartLine: 1, RootEndLine: 1, Signals: []string{artifacts.EntrySignalExternalLinkage}},
			{RootSymbolID: symB, RootName: "entry_b", RootPath: "b.c", RootModule: "modB", RootStartLine: 1, RootEndLine: 1, Signals: []string{artifacts.EntrySignalExternalLinkage}},
		},
		SurfacePartitions: []artifacts.SurfacePartition{
			{Bucket: artifacts.SurfaceBucketDispatchTables, Description: "dispatch", ClosureCount: 1, ModuleCount: 1, RootSymbolIDs: []artifacts.SymbolID{symA}},
			{Bucket: artifacts.SurfaceBucketStructBridges, Description: "bridges", ClosureCount: 1, ModuleCount: 1, RootSymbolIDs: []artifacts.SymbolID{symB}},
		},
	}
	if err := runfs.WriteJSON(runfs.BoundaryTopologyPath(run), topo); err != nil {
		t.Fatal(err)
	}
	cfg := RunConfig{
		RunID:              "sharded-test",
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

type funcLLMClient struct {
	fn func(ctx context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error)
}

func (f funcLLMClient) Generate(ctx context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	return f.fn(ctx, req)
}

func TestRunSharded_HappyPathParallelScoutsAndInvestigators(t *testing.T) {
	_, run, cfg := setupShardedFixture(t)
	var mu sync.Mutex
	scoutCalls := map[string]int{}
	scoutClient := funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
		msg := req.Messages[0].Content
		bucket := "unknown"
		file := "a.c"
		sym := "cpp:a.c:1:entry_a(int)"
		if strings.Contains(msg, "bucket=dispatch_tables") {
			bucket = "dispatch_tables"
		} else if strings.Contains(msg, "bucket=struct_bridges") {
			bucket = "struct_bridges"
			file = "b.c"
			sym = "cpp:b.c:1:entry_b(int)"
		}
		mu.Lock()
		scoutCalls[bucket]++
		step := scoutCalls[bucket]
		mu.Unlock()
		if step == 1 {
			b, _ := json.Marshal(map[string]any{"actions": []any{
				map[string]any{"name": "read_file", "args": map[string]any{"path": file, "start": 1, "end": 4}},
			}})
			return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
		}
		refMatch := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(msg)
		ref := ""
		if len(refMatch) == 2 {
			ref = refMatch[1]
		}
		b, _ := json.Marshal(map[string]any{"actions": []any{
			map[string]any{"name": "open_audit_lead", "args": map[string]any{
				"security_question": "Does " + file + " enforce bounds?",
				"target_symbol_ids": []string{sym},
				"reason":            []string{"Read boundary entry in " + file},
				"reason_fact_refs":  []string{ref},
			}},
			map[string]any{"name": "done", "args": map[string]any{"summary": "scout done"}},
		}})
		return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
	}}

	invClient := funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
		msg := req.Messages[0].Content
		leadMatch := regexp.MustCompile(`ISOLATED LEAD INVESTIGATION \((lead-s0-\d+)`).FindStringSubmatch(msg)
		leadID := leadMatch[1]
		if strings.Contains(msg, "a.c") {
			b, _ := json.Marshal(map[string]any{"actions": []any{
				map[string]any{"name": "formalize_contract", "args": map[string]any{
					"lead_id": leadID,
					"contract": artifacts.CaseInvariantV2{
						LeadRef:          leadID,
						Subjects:         []artifacts.ContractSubject{{Path: "a.c", Symbol: "entry_a"}},
						Preconditions:    []string{"entry_a is called with untrusted x"},
						RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "entry_a rejects negative x"},
						SecurityEffect:   "input acceptance",
					},
				}},
				map[string]any{"name": "done", "args": map[string]any{"summary": "formalized a.c"}},
			}})
			return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
		}
		refMatch := regexp.MustCompile(`reason_fact_refs: \[(\S+)\]`).FindStringSubmatch(msg)
		b, _ := json.Marshal(map[string]any{"actions": []any{
			map[string]any{"name": "close_lead", "args": map[string]any{
				"lead_id":   leadID,
				"reason":    "entry_b is a benign passthrough",
				"fact_refs": []string{refMatch[1]},
			}},
			map[string]any{"name": "done", "args": map[string]any{"summary": "closed b.c"}},
		}})
		return llm.GenerateResponse{Text: string(b), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
	}}

	cfg.ScoutClient = scoutClient
	cfg.Client = invClient
	res := RunSharded(context.Background(), cfg)
	if res.Err != nil {
		t.Fatalf("RunSharded failed: %v", res.Err)
	}
	if res.Bundle.PlannerMeta.TerminationReason != "sharded_done" {
		t.Fatalf("TerminationReason = %q, want sharded_done", res.Bundle.PlannerMeta.TerminationReason)
	}
	if len(res.CasePacks) != 1 || len(res.CasePacks[0].CaseInvariants) != 1 {
		t.Fatalf("expected 1 contracted CasePack, got %+v", res.CasePacks)
	}
	var ledger artifacts.CoverageLedger
	if err := runfs.ReadJSON(runfs.CoverageLedgerPath(run), &ledger); err != nil {
		t.Fatal(err)
	}
	if len(ledger.BySample) != 1 || ledger.BySample[0].ReconStatus != reconStatusSatisfied {
		t.Fatalf("expected satisfied coverage ledger, got %+v", ledger.BySample)
	}
}

// Codex Review #1 [P1] Regression: A transient 502/timeout in one scout shard MUST
// NOT be masked as `sharded_done` + `satisfied`.
func TestRunSharded_ShardFailureNeverMasksAsSatisfied(t *testing.T) {
	_, run, cfg := setupShardedFixture(t)
	cfg.ScoutClient = funcLLMClient{fn: func(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
		if strings.Contains(req.Messages[0].Content, "bucket=struct_bridges") {
			return llm.GenerateResponse{}, errors.New("HTTP 502 Bad Gateway")
		}
		return llm.GenerateResponse{
			Text:  `{"actions":[{"name":"done","args":{"summary":"ok"}}]}`,
			Usage: llm.Usage{PromptTokens: 50, CompletionTokens: 10, TotalTokens: 60},
		}, nil
	}}
	cfg.Client = cfg.ScoutClient

	res := RunSharded(context.Background(), cfg)
	if res.Bundle.PlannerMeta.TerminationReason == "sharded_done" {
		t.Fatalf("failed shard was masked as sharded_done: %+v", res.Bundle)
	}
	var ledger artifacts.CoverageLedger
	if err := runfs.ReadJSON(runfs.CoverageLedgerPath(run), &ledger); err != nil {
		t.Fatal(err)
	}
	if len(ledger.BySample) != 1 || ledger.BySample[0].ReconStatus == reconStatusSatisfied {
		t.Fatalf("failed shard was masked as satisfied coverage: %+v", ledger.BySample)
	}
}
