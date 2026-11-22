package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestReasoningBudgetInputEstimateHandlesCodeAndCJK(t *testing.T) {
	code := strings.Repeat("a", 35000)
	got := estimateRequestInputTokens("system", code)
	if got <= len(code)/4 || got >= len(code)/2 {
		t.Fatalf("35KB ASCII input estimate=%d; want a token estimate between quarter and half its byte length", got)
	}
	cjk := estimateRequestInputTokens("", strings.Repeat("契", 1000))
	if cjk < 2000 {
		t.Fatalf("CJK estimate=%d; non-ASCII characters must not be treated as three ASCII bytes", cjk)
	}
	if ascii := estimateRequestInputTokens("", strings.Repeat("a", 3000)); cjk <= ascii {
		t.Fatalf("equal-byte CJK/ASCII estimates=%d/%d; want a larger CJK estimate", cjk, ascii)
	}
}

func TestReasoningBudgetMinimumFollowsModelAndRoleLimit(t *testing.T) {
	for _, tc := range []struct {
		model, effort string
		limit, want   int
	}{
		{"glm-5.3", "", 32768, 16384},
		{"glm-4.7", "", 32768, 16384},
		{"deepseek-reasoner", "", 32768, 16384},
		{"o3", "", 32768, 16384},
		{"gpt-5.2", "", 32768, 16384},
		{"gateway-model", "high", 32768, 16384},
		{"gateway-model", "none", 32768, 256},
		{"ordinary-model", "", 32768, 256},
		{"glm-5.3", "", 8192, 8192},
	} {
		t.Run(tc.model+"/"+tc.effort, func(t *testing.T) {
			cfg := RunConfig{Model: tc.model, ReasoningEffort: tc.effort, MaxOutputTokens: tc.limit}
			if got := minimumRequestOutput(cfg); got != tc.want {
				t.Fatalf("minimum=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestReasoningBudgetIndependentLimitsAndRoleOutputCap(t *testing.T) {
	for _, tc := range []struct {
		name              string
		total, recon, inv int
		inRecon           bool
		want              int
	}{
		{"all token caps disabled", 0, 0, 0, false, 32768},
		{"only reconnaissance cap", 0, 25000, 0, true, 24000},
		{"only investigation cap", 0, 0, 22000, false, 21000},
		{"only aggregate cap", 20000, 0, 0, false, 19000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := RunConfig{MaxOutputTokens: 32768, Budget: Budget{MaxTokens: tc.total, MaxReconTokens: tc.recon, MaxInvestigationTokens: tc.inv}}
			if got := requestOutputBudget(cfg, 1000, tc.inRecon, true); got != tc.want {
				t.Fatalf("request output=%d want=%d", got, tc.want)
			}
		})
	}
}

// Reuse the action protocol exercised by the existing closing tests, but let
// the closing call keep the role's complete output allowance.
type reasoningBudgetClosingClient struct {
	inner closingIntegrationClient
}

func (c *reasoningBudgetClosingClient) Generate(ctx context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	if len(c.inner.requests) < 3 {
		return c.inner.Generate(ctx, req)
	}
	c.inner.requests = append(c.inner.requests, req)
	if len(c.inner.requests) != 4 {
		c.inner.t.Fatalf("unexpected extra model request: %d", len(c.inner.requests))
	}
	var input formalizationInput
	if err := json.Unmarshal([]byte(req.Messages[0].Content), &input); err != nil || len(input.Candidates) != 1 || len(input.Sources) != 1 {
		c.inner.t.Fatalf("closing request lost grounded input: %v / %+v", err, input)
	}
	data, err := json.Marshal(map[string]any{"formalizations": []any{map[string]any{
		"candidate_index":  0,
		"case_invariants":  []artifacts.CaseInvariantV2{closingTestContract()},
		"missing_evidence": []string{},
	}}})
	return llm.GenerateResponse{Text: string(data), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, err
}

func TestReasoningBudgetUnlimitedRunAndClosingKeepRoleAllowance(t *testing.T) {
	root, run := reliabilityFixture(t)
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		RunID: "reliable", Repository: artifacts.RepositoryCard{FileCount: 1},
		Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityUnavailable},
	}); err != nil {
		t.Fatal(err)
	}
	client := &reasoningBudgetClosingClient{inner: closingIntegrationClient{t: t}}
	budget := NewDefaultBudget()
	budget.MaxTokens, budget.MaxReconTokens, budget.MaxInvestigationTokens = 0, 0, 0
	result := Run(context.Background(), RunConfig{
		RunID: "reliable", RepoRoot: root, RunDir: run, Client: client,
		Registry: actions.NewDefaultRegistryWithNav(), Budget: budget,
		Model: "glm-5.3", MaxOutputTokens: 32768,
	})
	if result.Err != nil || result.Bundle.PlannerMeta.TerminationReason != "llm_done" {
		t.Fatalf("run failed: %v / %+v", result.Err, result.Bundle.PlannerMeta)
	}
	if len(client.inner.requests) != 4 {
		t.Fatalf("wanted three discovery requests and contract closing, got %d", len(client.inner.requests))
	}
	for i, req := range client.inner.requests {
		if req.MaxOutputTokens != 32768 {
			t.Fatalf("request %d output=%d; role allowance was silently clamped", i+1, req.MaxOutputTokens)
		}
	}
	assertClosingContract(t, result)
}

func TestReasoningBudgetTooSmallDoesNotDispatchUndersizedReply(t *testing.T) {
	root, run := reliabilityFixture(t)
	client := &reliabilityClient{}
	budget := NewDefaultBudget()
	budget.MaxTokens, budget.MaxReconTokens, budget.MaxInvestigationTokens = 9000, 0, 0
	budget.MaxReconRounds = 0
	result := Run(context.Background(), RunConfig{
		RunID: "reliable", RepoRoot: root, RunDir: run, Client: client,
		Registry: actions.NewDefaultRegistryWithNav(), Budget: budget,
		Model: "glm-5.3", MaxOutputTokens: 32768,
	})
	if len(client.requests) != 0 {
		t.Fatalf("dispatched %d requests even though the total cap cannot fit the reasoning minimum", len(client.requests))
	}
	if result.Err != nil || result.Bundle.PlannerMeta.TerminationReason == "llm_error" {
		t.Fatalf("insufficient budget was reported as a model failure: %v / %+v", result.Err, result.Bundle.PlannerMeta)
	}
	if len(result.Bundle.CoverageGaps) == 0 {
		t.Fatal("budget termination did not record incomplete coverage")
	}
}

func TestReasoningBudgetReconAllowanceTransitionsBeforeDispatch(t *testing.T) {
	root, run := reliabilityFixture(t)
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		RunID: "reliable", Repository: artifacts.RepositoryCard{FileCount: 40},
		Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityAvailable},
	}); err != nil {
		t.Fatal(err)
	}
	client := &reliabilityClient{firstText: `{"actions":[{"name":"done","args":{"summary":"budget transition","candidates":[]}}]}`}
	budget := NewDefaultBudget()
	budget.MaxTokens, budget.MaxReconTokens, budget.MaxInvestigationTokens = 0, 9000, 0
	result := Run(context.Background(), RunConfig{
		RunID: "reliable", RepoRoot: root, RunDir: run, Client: client,
		Registry: actions.NewDefaultRegistryWithNav(), Budget: budget,
		Model: "glm-5.3", MaxOutputTokens: 32768,
	})
	if result.Err != nil || len(client.requests) == 0 {
		t.Fatalf("phase transition failed: %v / %d requests", result.Err, len(client.requests))
	}
	first := client.requests[0]
	if !strings.Contains(first.SystemPrompt, "Investigator") || first.MaxOutputTokens != 32768 {
		t.Fatalf("first dispatch still uses the exhausted reconnaissance allowance: output=%d system=%s", first.MaxOutputTokens, first.SystemPrompt)
	}
}

func TestReasoningBudgetPromptLabelsDisabledCapsAsUnlimited(t *testing.T) {
	budget := NewDefaultBudget()
	budget.MaxTokens, budget.MaxReconTokens, budget.MaxInvestigationTokens = 0, 0, 0
	budget.TokensUsed, budget.ReconTokensUsed, budget.InvestigationTokensUsed = 3456, 1234, 2222
	prompt := BuildRoundPrompt(NewState("budget-labels"), PromptProfile{}, budget, nil)
	for _, want := range []string{
		"tokens: 3456/unlimited",
		"reconnaissance tokens: 1234/unlimited",
		"investigation tokens: 2222/unlimited",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("missing disabled-cap label %q in prompt:\n%s", want, prompt)
		}
	}
	for _, wrong := range []string{"tokens: 3456/0", "tokens: 1234/0", "tokens: 2222/0"} {
		if strings.Contains(prompt, wrong) {
			t.Fatalf("disabled budget was presented as exhausted: %q", wrong)
		}
	}
}

type reasoningBudgetBlockedClient struct {
	calls    int
	deadline time.Time
}

func (c *reasoningBudgetBlockedClient) Generate(ctx context.Context, _ llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	var ok bool
	c.deadline, ok = ctx.Deadline()
	if !ok || time.Until(c.deadline) > time.Second {
		// Fail promptly if a regression stops passing the Planner deadline,
		// rather than hanging the entire test on an unbounded client call.
		return llm.GenerateResponse{}, fmt.Errorf("ordinary Planner request lacks its bounded wall-clock deadline")
	}
	<-ctx.Done()
	return llm.GenerateResponse{}, ctx.Err()
}

func TestReasoningBudgetUnlimitedTokensStillBoundOrdinaryRequestTime(t *testing.T) {
	root, run := reliabilityFixture(t)
	client := &reasoningBudgetBlockedClient{}
	budget := NewDefaultBudget()
	budget.MaxTokens, budget.MaxReconTokens, budget.MaxInvestigationTokens = 0, 0, 0
	budget.MaxReconRounds = 0
	budget.WallClock = 500 * time.Millisecond
	started := time.Now()
	result := Run(context.Background(), RunConfig{
		RunID: "reliable", RepoRoot: root, RunDir: run, Client: client,
		Registry: actions.NewDefaultRegistryWithNav(), Budget: budget,
		Model: "glm-5.3", MaxOutputTokens: 32768,
	})
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("wall-clock limited run took %s", elapsed)
	}
	if client.calls != 1 || client.deadline.IsZero() {
		t.Fatalf("normal request was not bounded: calls=%d deadline=%s", client.calls, client.deadline)
	}
	if result.Err != nil || result.Bundle.PlannerMeta.TerminationReason == "llm_error" {
		t.Fatalf("wall-clock expiry was treated as a provider error: %v / %+v", result.Err, result.Bundle.PlannerMeta)
	}
	if result.Bundle.PlannerMeta.TerminationReason != "wall_clock" && !strings.Contains(strings.Join(result.Bundle.CoverageGaps, "\n"), "wall_clock") {
		t.Fatalf("wall-clock termination lost its reason: %+v / %v", result.Bundle.PlannerMeta, result.Bundle.CoverageGaps)
	}
}
