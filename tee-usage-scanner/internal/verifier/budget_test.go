package verifier

import (
	"context"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

type budgetLLM struct {
	calls    int
	response string
}

func (s *budgetLLM) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	s.calls++
	return llm.GenerateResponse{Text: s.response}, nil
}

func TestVerifierBoundsTotalBusQueries(t *testing.T) {
	client := &budgetLLM{response: `{"queries":[{"to_agent":"expert-001","question":"check"},{"to_agent":"expert-001","question":"check again"}]}`}
	bus := agentbus.New(100)
	queries := 0
	bus.Register("expert-001", func(context.Context, agentbus.Query) (agentbus.Response, error) {
		queries++
		return agentbus.Response{FromAgent: "expert-001", Answer: "evidence"}, nil
	})
	memo, err := buildMemoLLM(context.Background(), client, bus, t.TempDir(), artifacts.CasePack{CaseID: "budget"}, artifacts.Hypothesis{}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if queries > 4 || client.calls > 2 {
		t.Fatalf("unbounded review: queries=%d llm=%d", queries, client.calls)
	}
	if memo.Status != "inconclusive" || !strings.Contains(strings.Join(memo.Notes, " "), "budget") {
		t.Fatalf("want deterministic budget outcome, got %+v", memo)
	}
}

func TestVerifierRejectsOversizedInitialContextWithoutCallingModel(t *testing.T) {
	client := &budgetLLM{response: `{"status":"corroborated"}`}
	memo, err := buildMemoLLM(context.Background(), client, agentbus.New(3), t.TempDir(), artifacts.CasePack{CaseID: "large"}, artifacts.Hypothesis{Title: strings.Repeat("x", 200*1024)}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 0 || memo.Status != "inconclusive" {
		t.Fatalf("oversized context reached model: calls=%d memo=%+v", client.calls, memo)
	}
}

func TestVerifierStopsBeforeFollowingOversizedBusResponse(t *testing.T) {
	client := &budgetLLM{response: `{"queries":[{"to_agent":"expert-001","question":"check"}]}`}
	bus := agentbus.New(100)
	bus.Register("expert-001", func(context.Context, agentbus.Query) (agentbus.Response, error) {
		return agentbus.Response{FromAgent: "expert-001", Answer: strings.Repeat("x", 200*1024)}, nil
	})
	memo, err := buildMemoLLM(context.Background(), client, bus, t.TempDir(), artifacts.CasePack{CaseID: "response"}, artifacts.Hypothesis{Title: strings.Repeat("x", 110*1024)}, artifacts.Challenge{}, caseContext{}, "verifier-001", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 || memo.Status != "inconclusive" {
		t.Fatalf("large response recirculated: calls=%d memo=%+v", client.calls, memo)
	}
}
