package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codedb"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/codeql"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/taint"
)

type traceIntegrationDB struct {
	calls int
	scope codedb.Scope
}

func (d *traceIntegrationDB) Ensure(_ context.Context, scope codedb.Scope) (string, error) {
	d.calls++
	d.scope = scope
	return "shared-existing-codeql-db", nil
}
func (*traceIntegrationDB) Path(codedb.Scope) string  { return "shared-existing-codeql-db" }
func (*traceIntegrationDB) State(codedb.Scope) string { return codedb.StateReady }

type traceIntegrationEngine struct {
	createCalls  int
	analyzeCalls int
}

func (*traceIntegrationEngine) Available() bool { return true }
func (e *traceIntegrationEngine) CreateDatabase(context.Context, codeql.CreateDBOptions) error {
	e.createCalls++
	return fmt.Errorf("trace must reuse the supplied DB provider")
}
func (e *traceIntegrationEngine) Analyze(_ context.Context, options codeql.AnalyzeOptions) ([]codeql.Result, error) {
	e.analyzeCalls++
	if options.DBPath != "shared-existing-codeql-db" || options.MaxPaths != 10 {
		return nil, fmt.Errorf("unexpected DB or witness bound: %q / %d", options.DBPath, options.MaxPaths)
	}
	return []codeql.Result{{Path: "entry.c", StartLine: 1, Paths: [][]codeql.PathStep{{
		{Path: "entry.c", StartLine: 2, Function: "entry", Expression: "value"},
		{Path: "entry.c", StartLine: 1, Function: "consume", Expression: "consume(value)"},
	}}}}, nil
}

type traceIntegrationClient struct {
	t       *testing.T
	calls   int
	factRef string
}

func (c *traceIntegrationClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.t.Helper()
	c.calls++
	action := func(name string, args any) map[string]any { return map[string]any{"name": name, "args": args} }
	var selected []any
	switch c.calls {
	case 1:
		selected = []any{action("read_file", map[string]any{"path": "entry.c", "start": 1, "end": 2})}
	case 2:
		match := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
		if len(match) != 2 {
			c.t.Fatalf("source observation not presented: %s", req.Messages[0].Content)
		}
		selected = []any{action("open_audit_lead", map[string]any{
			"security_question": "Does entry validate the input before forwarding it?",
			"target_symbol_ids": []string{"cpp:entry.c:2:entry(int)"},
			"reason":            []string{"The observed definition forwards the supplied value."},
			"reason_fact_refs":  []string{match[1]},
		})}
	case 3:
		args := map[string]any{"source_func": "entry", "source_param_index": 0, "sink_func": "consume", "max_paths": 5, "max_hops": 12}
		// The second call must remain available after the single-query quota
		// is spent, because it reuses the same immutable cached fact.
		selected = []any{action("trace_taint", args), action("trace_taint", args)}
	case 4:
		prompt := req.Messages[0].Content
		if !strings.Contains(prompt, "uncached taint query attempts: 1/1") || !regexp.MustCompile(`"cache_hit"\s*:\s*true`).MatchString(prompt) {
			c.t.Fatalf("cache hit spent quota or was not exposed: %s", prompt)
		}
		match := regexp.MustCompile(`"fact_ref"\s*:\s*"([^"]+)"`).FindStringSubmatch(prompt)
		if len(match) != 2 {
			c.t.Fatalf("trace did not expose its immutable fact reference: %s", prompt)
		}
		c.factRef = match[1]
		contract := artifacts.CaseInvariantV2{
			Subjects:            []artifacts.ContractSubject{{Path: "entry.c", Symbol: "entry"}},
			Preconditions:       []string{"entry receives an input that requires validation"},
			RequiredProperty:    artifacts.ContractProperty{Kind: "input_guard", Statement: "entry validates the input before forwarding it"},
			SecurityEffect:      "the consumer receives validated input",
			VerificationQueries: []artifacts.ContractQuery{},
			// Deliberately no EvidenceRefs: the lead already owns the trace.
		}
		selected = []any{
			action("update_lead", map[string]any{"lead_id": "lead-s0-001", "add_taint_fact_refs": []string{c.factRef}}),
			action("formalize_contract", map[string]any{"lead_id": "lead-s0-001", "contract": contract}),
		}
	case 5:
		selected = []any{action("done", map[string]any{"summary": "Recorded a source-bound obligation and supporting may-flow evidence.", "candidates": []any{}})}
	default:
		c.t.Fatalf("unexpected model call %d", c.calls)
	}
	body, err := json.Marshal(map[string]any{"actions": selected})
	if err != nil {
		return llm.GenerateResponse{}, err
	}
	return llm.GenerateResponse{Text: string(body), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 100, TotalTokens: 200}}, nil
}

func TestPlannerRunTraceTaintLeadContractChainUsesSharedDB(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.c"), []byte("int consume(int value) { return value; }\nint entry(int value) { return consume(value); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := runfs.BuildScope("fixture", "revision", root)
	manifest := artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "taint-integration", RepoURL: "fixture", Commit: "revision", LocalPath: root, Scope: scope, Focus: "tee"}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), manifest); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.RepoFactsPath(run), artifacts.RepoFacts{
		RunID: manifest.RunID, Scope: scope, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable},
		Symbols: []artifacts.Symbol{{SymbolID: "cpp:entry.c:2:entry(int)", Name: "entry", File: "entry.c", StartLine: 2, Signature: "(int)"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		RunID: manifest.RunID, Scope: scope, Repository: artifacts.RepositoryCard{FileCount: 1}, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable},
	}); err != nil {
		t.Fatal(err)
	}
	db, engine := &traceIntegrationDB{}, &traceIntegrationEngine{}
	client := &traceIntegrationClient{t: t}
	budget := NewDefaultBudget()
	budget.MaxReconRounds = 0
	budget.MaxTaintQueries = 1
	result := Run(context.Background(), RunConfig{
		RunID: manifest.RunID, RepoRoot: root, RunDir: run, Profile: PromptProfile{RepoURL: manifest.RepoURL, Commit: manifest.Commit},
		Client: client, Registry: actions.NewDefaultRegistryWithFacts(engine, db, "", nil), Budget: budget,
	})
	if result.Err != nil || result.Bundle.PlannerMeta.TerminationReason != "llm_done" {
		t.Fatalf("run failed: %v %+v", result.Err, result.Bundle)
	}
	if client.calls != 5 || engine.analyzeCalls != 1 || engine.createCalls != 0 || db.calls != 1 {
		t.Fatalf("unexpected LLM/analyze/create/ensure calls: %d/%d/%d/%d", client.calls, engine.analyzeCalls, engine.createCalls, db.calls)
	}
	if db.scope.Repository != manifest.RepoURL || db.scope.Commit != manifest.Commit || db.scope.RunDir != run {
		t.Fatalf("wrong shared DB scope: %+v", db.scope)
	}
	if len(result.CasePacks) != 1 || len(result.CasePacks[0].CaseInvariants) != 1 {
		t.Fatalf("contract missing or duplicated: %+v errors=%+v", result.CasePacks, result.Bundle.Errors)
	}
	contract := result.CasePacks[0].CaseInvariants[0]
	binding := contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: scope}
	if err := contracts.Validate(contract, binding); err != nil {
		t.Fatalf("contract no longer validates: %v", err)
	}
	var inherited []artifacts.ContractEvidenceRef
	for _, ref := range contract.EvidenceRefs {
		if ref.Kind == "tool_fact" {
			inherited = append(inherited, ref)
		}
	}
	if len(inherited) != 1 || inherited[0].Ref != client.factRef || inherited[0].ContentSHA256 == "" {
		t.Fatalf("lead-owned taint fact was not bound automatically: %+v", contract.EvidenceRefs)
	}
	fact, err := contracts.LoadToolFact(inherited[0].Ref, binding)
	if err != nil || fact.Operation != taint.Operation || fact.Scope == nil || fact.Status != "success" || len(fact.Paths) != 1 {
		t.Fatalf("invalid inherited fact: %+v err=%v", fact, err)
	}
	if err := artifacts.ValidateToolFactContent(fact); err != nil {
		t.Fatal(err)
	}
	leads, err := contractLeads(RunConfig{RunID: manifest.RunID, RunDir: run})
	if err != nil || len(leads["lead-s0-001"].TaintFactRefs) != 1 {
		t.Fatalf("lead lost trace reference: %+v %v", leads, err)
	}
}
