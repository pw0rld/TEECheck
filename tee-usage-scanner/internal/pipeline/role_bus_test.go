package pipeline

import (
	"context"
	"fmt"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
)

type roleBusClient struct {
	calls       int
	temperature float64
}

func (c *roleBusClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	c.temperature = req.Temperature
	return llm.GenerateResponse{Text: `{"answer":"checked","facts":[]}`}, nil
}

func TestRoleBusRoutesReviewerToVerifierClient(t *testing.T) {
	e, v, c := &roleBusClient{}, &roleBusClient{}, &roleBusClient{}
	clients := RoleClients{Expert: e, Verifier: v, Challenger: c}
	settings := map[string]config.Config{"expert": {LLMTemp: 0.1}, "verifier": {LLMTemp: 0.2}, "challenger": {LLMTemp: 0.3}}
	bus := buildPipelineBus(config.Config{}, func(agent string) llm.Client { return clients.forRole(agentRole(agent)) }, settings)
	for i, target := range []string{"expert-001", "reviewer-001", "challenger-001"} {
		_, err := bus.AskForCase(context.Background(), "case", agentbus.Query{QueryID: fmt.Sprint(i), FromAgent: "arbiter-001", ToAgent: target, Question: "check", Evidence: "Synthetic case: int verify(int value) { return value > 0; }"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if e.calls != 1 || v.calls != 1 || c.calls != 1 || e.temperature != 0.1 || v.temperature != 0.2 || c.temperature != 0.3 {
		t.Fatalf("wrong role routing: expert=%+v verifier=%+v challenger=%+v", e, v, c)
	}
}

func TestRoleClientsMissingRoleFailsBeforeRun(t *testing.T) {
	if _, err := RunWithClients(config.Config{}, RoleClients{}); err == nil {
		t.Fatal("missing role clients should fail before source acquisition")
	}
}
