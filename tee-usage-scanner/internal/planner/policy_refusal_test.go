package planner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

type policyRefusalClient struct {
	requests                    []llm.GenerateRequest
	malformedFirstInvestigation bool
}

func (c *policyRefusalClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.requests = append(c.requests, req)
	switch len(c.requests) {
	case 1:
		return llm.GenerateResponse{Text: `{"actions":[{"name":"get_repository_card","args":{}},{"name":"list_dir","args":{"path":".","depth":1}},{"name":"read_file","args":{"path":"a.c","start":1,"end":4}}]}`}, nil
	case 2:
		ref := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
		if len(ref) != 2 {
			return llm.GenerateResponse{}, errors.New("source observation unavailable")
		}
		payload := map[string]any{"actions": []any{map[string]any{
			"name": "open_audit_lead", "args": map[string]any{
				"security_question": "Does verify enforce its input contract?",
				"target_symbol_ids": []string{"a.c::verify"},
				"reason":            []string{"The source contains a verification decision."},
				"reason_fact_refs":  []string{ref[1]},
			},
		}}}
		body, _ := json.Marshal(payload)
		return llm.GenerateResponse{Text: string(body)}, nil
	case 3:
		if c.malformedFirstInvestigation {
			return llm.GenerateResponse{Text: "not a structured response"}, nil
		}
		fallthrough
	default:
		return llm.GenerateResponse{Raw: "policy-refusal-response"}, errors.New("upstream status 502: flagged for possible cybersecurity risk")
	}
}

func TestPlannerRun_PassBPolicyRefusalPreservesLeadAndStops(t *testing.T) {
	checkPolicyRefusalCheckpoint(t, false)
}

func TestPlannerRun_PolicyRefusalDuringFormatRetryPreservesLeadAndStops(t *testing.T) {
	checkPolicyRefusalCheckpoint(t, true)
}

func checkPolicyRefusalCheckpoint(t *testing.T, malformedFirst bool) {
	t.Helper()
	root, run := reliabilityFixture(t)
	project := artifacts.ProjectMap{
		RunID: "reliable", Repository: artifacts.RepositoryCard{FileCount: 1},
		Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityUnavailable},
	}
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), project); err != nil {
		t.Fatal(err)
	}
	client := &policyRefusalClient{malformedFirstInvestigation: malformedFirst}
	result := Run(context.Background(), RunConfig{
		RunID: "reliable", RepoRoot: root, RunDir: run, Client: client,
		Registry: actions.NewDefaultRegistryWithNav(), Budget: NewDefaultBudget(),
		TWEContext: "test knowledge catalog marker",
	})
	if result.Err == nil || result.Bundle == nil {
		t.Fatal("refusal must stop the run with its evidence bundle intact")
	}
	wantCalls := 3
	if malformedFirst {
		wantCalls++
	}
	if len(client.requests) != wantCalls {
		t.Fatalf("policy refusal must not trigger a rewritten request: %d requests", len(client.requests))
	}
	if !strings.Contains(client.requests[2].SystemPrompt, "test knowledge catalog marker") {
		t.Fatal("test did not reach the knowledge-backed investigation request")
	}
	if result.Bundle.PlannerMeta.TerminationReason != "policy_refusal" {
		t.Fatalf("termination=%q, want explicit policy_refusal", result.Bundle.PlannerMeta.TerminationReason)
	}
	leads, err := os.ReadFile(runfs.AuditLeadsPath(run))
	if err != nil || !strings.Contains(string(leads), "Does verify enforce its input contract?") {
		t.Fatalf("opened lead lost: %s (%v)", leads, err)
	}
	for _, path := range []string{runfs.EvidenceBundlePath(run), runfs.RoundsLogPath(run)} {
		body, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(body), "coverage_gaps") || !strings.Contains(string(body), "upstream policy refusal") {
			t.Fatalf("refusal coverage gap not recorded in %s: %s (%v)", path, body, err)
		}
	}
}
