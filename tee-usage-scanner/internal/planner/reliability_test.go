package planner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestReliability_DefaultTokenPartitions(t *testing.T) {
	b := NewDefaultBudget()
	if b.MaxTokens != 240000 || b.MaxReconTokens != 100000 || b.MaxInvestigationTokens != 140000 || b.ConvergenceReserveTokens != 20000 {
		t.Fatalf("wrong token partitions: %+v", b)
	}
}
func TestReliability_IndexedGate(t *testing.T) {
	r := NewReconState(ReconModeIndexed)
	r.Observe("get_repository_card", "", true)
	for _, m := range []string{"core/a", "core/b", "core/c"} {
		r.Observe("list_functions", m, true)
	}
	for i := 0; i < 6; i++ {
		r.Observe("get_function_card", string(rune('a'+i))+":core/"+[]string{"a", "b"}[i%2]+"/f.c:1:f()", true)
	}
	r.Observe("get_callers", "cpp:core/a/f.c:1:f()", true)
	if !r.AllowLead() {
		t.Fatalf("3/6/2 must permit lead: %s", r.Unmet())
	}
}
func TestReliability_TreeOnlyLead(t *testing.T) {
	for _, target := range []string{"src/a.c", "src/a.c::verify", "cpp:src/a.c:12:verify()", "src/missing.c", "../outside.c::verify", "cpp:src/a.c:30:verify()"} {
		t.Run(target, func(t *testing.T) {
			r := NewReconState(ReconModeTreeOnly)
			r.ObserveAction("read_file", json.RawMessage(`{"path":"src/a.c","start":10,"end":20}`), true)
			obs := ObservationSet{}
			obs.Record("obs:test", true)
			_, res := tryOpenAuditLead(r, obs, OpenAuditLeadPayload{SecurityQuestion: "q", TargetSymbolIDs: []artifacts.SymbolID{artifacts.SymbolID(target)}, Reason: []string{"r"}, ReasonFactRefs: []string{"obs:test"}})
			want := target == "src/a.c" || target == "src/a.c::verify" || target == "cpp:src/a.c:12:verify()"
			if res.OK != want {
				t.Fatalf("accepted=%v want=%v: %s", res.OK, want, res.Error)
			}
		})
	}
}

type reliabilityClient struct {
	requests   []llm.GenerateRequest
	firstUsage int
	firstText  string
}

func (c *reliabilityClient) Generate(_ context.Context, r llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.requests = append(c.requests, r)
	if len(c.requests) == 1 {
		return llm.GenerateResponse{Text: c.firstText, Usage: llm.Usage{PromptTokens: c.firstUsage, TotalTokens: c.firstUsage}}, nil
	}
	return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"bounded conclusion","candidates":[]}}]}`, Usage: llm.Usage{PromptTokens: 500, CompletionTokens: 100, TotalTokens: 600}}, nil
}
func reliabilityFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	run := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte("int verify(void) { return 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{SchemaVersion: "teecheck.manifest.v1", RunID: "reliable", LocalPath: root, Commit: "abc", Focus: "tee"}); err != nil {
		t.Fatal(err)
	}
	return root, run
}
func TestReliability_ReserveExecutesForcedDone(t *testing.T) {
	root, run := reliabilityFixture(t)
	c := &reliabilityClient{firstUsage: 185000, firstText: `{"actions":[{"name":"read_file","args":{"path":"a.c"}}]}`}
	b := NewDefaultBudget()
	b.MaxReconRounds = 0
	b.MaxInvestigationTokens = 200000
	got := Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Client: c, Registry: actions.NewDefaultRegistryWithNav(), Budget: b})
	if got.Err != nil {
		t.Fatal(got.Err)
	}
	if len(c.requests) != 2 || !strings.Contains(c.requests[1].Messages[0].Content, "FINAL ROUND") {
		t.Fatalf("reserve never produced final call: %#v", c.requests)
	}
	if c.requests[1].MaxOutputTokens <= 0 || c.requests[1].MaxOutputTokens > 15000 {
		t.Fatalf("unbounded final request: %+v", c.requests[1])
	}
	if got.Bundle.FinalSummary != "bounded conclusion" {
		t.Fatalf("done not processed: %+v", got.Bundle)
	}
}
func TestReliability_ReconTokensReleaseGate(t *testing.T) {
	root, run := reliabilityFixture(t)
	m := artifacts.ProjectMap{RunID: "reliable", SchemaVersion: artifacts.SchemaVersionProjectMapV1, Repository: artifacts.RepositoryCard{FileCount: 40}}
	m.Capabilities.Symbols = artifacts.CapabilityAvailable
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), m); err != nil {
		t.Fatal(err)
	}
	c := &reliabilityClient{firstUsage: NewDefaultBudget().MaxReconTokens, firstText: `{"actions":[{"name":"read_file","args":{"path":"a.c"}}]}`}
	got := Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Client: c, Registry: actions.NewDefaultRegistryWithNav(), Budget: NewDefaultBudget()})
	if got.Err != nil {
		t.Fatal(got.Err)
	}
	if len(c.requests) != 2 || !strings.Contains(c.requests[1].SystemPrompt, "Investigator") {
		t.Fatalf("token gate did not release: %#v", c.requests)
	}
}
func TestReliability_RoundPromptUsesCeiling(t *testing.T) {
	b := NewDefaultBudget()
	b.RoundsUsed = 5
	b.ReconRoundsUsed = 5
	if s := BuildRoundPrompt(NewState("r"), PromptProfile{}, b, nil); !strings.Contains(s, "rounds: 5/13") {
		t.Fatalf("wrong round ceiling: %s", s)
	}
}

func TestReliability_ObservationRefsAreNotToolFactFiles(t *testing.T) {
	root, run := reliabilityFixture(t)
	fact := filepath.Join(run, "fact.json")
	if err := os.WriteFile(fact, []byte(`{"status":"success"}`), 0600); err != nil {
		t.Fatal(err)
	}
	raw := []map[string]any{{"tool_fact_refs": []string{"obs:round-1", fact}, "filled_roles": map[string]any{"source": map[string]any{"path": "a.c", "start_line": 1, "symbol": "verify"}}}}
	invs, _, diagnostics := processInvestigations(raw, RunConfig{RepoRoot: root, RunDir: run}, nil, nil)
	if len(invs) != 1 || len(invs[0].ToolFactRefs) != 1 || invs[0].ToolFactRefs[0] != fact {
		t.Fatalf("wrong references: %+v", invs)
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[0].Error, "observation reference") {
		t.Fatalf("dropped obs without diagnostic: %+v", diagnostics)
	}
}

func TestReliability_IsFinalRoundIncludesTokenReserve(t *testing.T) {
	b := NewDefaultBudget()
	b.TokensUsed = b.MaxTokens - b.ConvergenceReserveTokens - 1
	b.InvestigationTokensUsed = 119999
	if b.IsFinalRound() {
		t.Fatal("premature final before reserve")
	}
	b.TokensUsed = b.MaxTokens - b.ConvergenceReserveTokens
	if !b.IsFinalRound() {
		t.Fatal("total reserve must trigger final")
	}
	b.TokensUsed = 0
	b.InvestigationTokensUsed = 120000
	if !b.IsFinalRound() {
		t.Fatal("investigation reserve must trigger final")
	}
}
func TestReliability_AllowanceIncludesInputAndReserve(t *testing.T) {
	b := NewDefaultBudget()
	b.TokensUsed = 165000
	b.InvestigationTokensUsed = 105000
	if got := b.OutputAllowance(20000, false, false); got != 0 {
		t.Fatalf("ordinary call crosses reserve: %d", got)
	}
	if got := b.OutputAllowance(20000, false, true); got != 15000 {
		t.Fatalf("final reply allowance=%d", got)
	}
}

type phaseSwitchClient struct {
	calls    int
	requests []llm.GenerateRequest
}

func (c *phaseSwitchClient) Generate(_ context.Context, r llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.requests = append(c.requests, r)
	c.calls++
	switch c.calls {
	case 1:
		return llm.GenerateResponse{Text: `{"actions":[{"name":"read_file","args":{"path":"a.c"}}]}`, Usage: llm.Usage{PromptTokens: NewDefaultBudget().MaxReconTokens - 1000}}, nil
	case 2:
		return llm.GenerateResponse{Text: `{"actions":[{"name":"twe_playbook_detail","args":{"twe_id":"TWE-STATE-001"}}]}`, Usage: llm.Usage{PromptTokens: 100}}, nil
	default:
		return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"ok","candidates":[]}}]}`, Usage: llm.Usage{PromptTokens: 100}}, nil
	}
}

type detailAfterSwitch struct{}

func (detailAfterSwitch) Name() string { return "twe_playbook_detail" }
func (detailAfterSwitch) Run(context.Context, actions.ActionRequest) actions.ActionResult {
	return actions.ActionResult{Name: "twe_playbook_detail", OK: true, Output: "detail now available"}
}
func TestReliability_TokenTransitionUnhidesInvestigationActions(t *testing.T) {
	root, run := reliabilityFixture(t)
	m := artifacts.ProjectMap{RunID: "reliable", SchemaVersion: artifacts.SchemaVersionProjectMapV1, Repository: artifacts.RepositoryCard{FileCount: 40}}
	m.Capabilities.Symbols = artifacts.CapabilityAvailable
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), m); err != nil {
		t.Fatal(err)
	}
	registry := actions.NewDefaultRegistryWithNav()
	registry.Register(detailAfterSwitch{})
	c := &phaseSwitchClient{}
	result := Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Client: c, Registry: registry, Budget: NewDefaultBudget()})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	data, err := os.ReadFile(runfs.RoundsLogPath(run))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "detail now available") {
		t.Fatalf("post-recon action remained hidden: %s", data)
	}
}

type sequenceBudgetClient struct {
	responses []llm.GenerateResponse
	requests  []llm.GenerateRequest
}

func (c *sequenceBudgetClient) Generate(_ context.Context, r llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.requests = append(c.requests, r)
	i := len(c.requests) - 1
	if i >= len(c.responses) {
		i = len(c.responses) - 1
	}
	return c.responses[i], nil
}
func TestReliability_MalformedRetryUsesConvergenceReserve(t *testing.T) {
	root, run := reliabilityFixture(t)
	b := NewDefaultBudget()
	b.MaxReconRounds = 0
	c := &sequenceBudgetClient{responses: []llm.GenerateResponse{{Text: "not JSON", Usage: llm.Usage{PromptTokens: 125000, CompletionTokens: 2}}, {Text: `{"actions":[{"name":"done","args":{"summary":"recovered","candidates":[]}}]}`, Usage: llm.Usage{PromptTokens: 500, CompletionTokens: 100}}}}
	result := Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Client: c, Registry: actions.NewDefaultRegistryWithNav(), Budget: b})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(c.requests) != 2 || !strings.Contains(c.requests[1].Messages[0].Content, "FINAL ROUND") || result.Bundle.FinalSummary != "recovered" {
		t.Fatalf("no executable convergence retry: %+v", result)
	}
}
func TestReliability_FinalRoundCannotBeBlockedByReconAllowance(t *testing.T) {
	root, run := reliabilityFixture(t)
	b := NewDefaultBudget()
	b.MaxRounds = 1
	b.MaxReconRounds = 1
	m := artifacts.ProjectMap{RunID: "reliable", SchemaVersion: artifacts.SchemaVersionProjectMapV1, Repository: artifacts.RepositoryCard{FileCount: 40}}
	m.Capabilities.Symbols = artifacts.CapabilityAvailable
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), m); err != nil {
		t.Fatal(err)
	}
	c := &reliabilityClient{firstUsage: 59000, firstText: `{"actions":[{"name":"read_file","args":{"path":"a.c"}}]}`}
	result := Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Client: c, Registry: actions.NewDefaultRegistryWithNav(), Budget: b})
	if result.Err != nil || len(c.requests) != 2 || result.Bundle.FinalSummary != "bounded conclusion" {
		t.Fatalf("recon allowance blocked natural final: %+v", result)
	}
}
func TestReliability_PartialUsageIsNotFree(t *testing.T) {
	in, out := accountedUsage(llm.GenerateResponse{Text: "{}", Usage: llm.Usage{CompletionTokens: 10}}, 400)
	if in != 400 || out != 10 {
		t.Fatalf("missing input was free: %d %d", in, out)
	}
	in, out = accountedUsage(llm.GenerateResponse{Text: "12345", Usage: llm.Usage{PromptTokens: 30}}, 400)
	if in != 30 || out != 5 {
		t.Fatalf("missing output was free: %d %d", in, out)
	}
	in, out = accountedUsage(llm.GenerateResponse{Text: "{}", Usage: llm.Usage{PromptTokens: 30, CompletionTokens: 10, TotalTokens: 70}}, 400)
	if in+out != 70 {
		t.Fatalf("provider total dropped: %d", in+out)
	}
}
