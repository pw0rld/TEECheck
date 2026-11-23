package pipeline_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/pipeline"
)

type roleClient struct {
	role  string
	calls int
}

type refusalRoleClient struct{ calls int }

func (c *refusalRoleClient) Generate(context.Context, llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	return llm.GenerateResponse{}, errors.New("content_policy_violation: synthetic refusal")
}

func TestRoleClientsDoNotRerouteAfterPolicyRefusal(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "demo.c"), []byte("int demo(void) { return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	refusing := &refusalRoleClient{}
	other := &roleClient{role: "expert"}
	_, err := pipeline.RunWithClients(config.Config{Command: "run", Target: root, RunID: "refusal", OutputDir: out, KnowledgeRoot: filepath.Join(out, "knowledge")}, pipeline.RoleClients{Planner: refusing, Default: other})
	if err == nil || !strings.Contains(err.Error(), "policy refusal") {
		t.Fatalf("refusal not surfaced: %v", err)
	}
	if refusing.calls != 1 || other.calls != 0 {
		t.Fatalf("refusal caused rerouting/retry: original=%d other=%d", refusing.calls, other.calls)
	}
}

func (c *roleClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.calls++
	if c.role == "planner" {
		switch c.calls {
		case 1:
			return llm.GenerateResponse{Text: `{"actions":[{"name":"list_dir","args":{"path":".","depth":1}},{"name":"read_file","args":{"path":"demo.c","start":1,"end":3}}]}`}, nil
		case 2:
			ref := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
			if len(ref) != 2 {
				return llm.GenerateResponse{}, fmt.Errorf("source observation missing")
			}
			body, _ := json.Marshal(map[string]any{"actions": []any{map[string]any{"name": "open_audit_lead", "args": map[string]any{"security_question": "Does demo verify its input?", "target_symbol_ids": []string{"demo.c::verify"}, "reason": []string{"Observed the implementation"}, "reason_fact_refs": []string{ref[1]}}}}})
			return llm.GenerateResponse{Text: string(body)}, nil
		default:
			return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"demo review","candidates":[{"id":"demo","kind":"attestation","priority":"low","paths":["demo.c"],"symbols":["verify"],"why_selected":["observed demo function"]}]}}]}`}, nil
		}
	}
	if c.role == "expert" {
		return llm.GenerateResponse{Text: `{"title":"Review demo","suspected_issue":"Check the input contract","confidence":"low","needs_verification":true}`}, nil
	}
	if c.role == "challenger" {
		return llm.GenerateResponse{Text: `{"issue_present":false,"summary":"No demonstrated issue","counter_arguments":["No unsafe behavior observed"]}`}, nil
	}
	if c.role == "verifier" {
		return llm.GenerateResponse{Text: `{"status":"inconclusive","queries":[],"notes":["No demonstrated issue"]}`}, nil
	}
	return llm.GenerateResponse{Text: `{"status":"needs_review","severity":"low","confidence":"low","summary":"Manual review required","human_review_questions":["Confirm the contract"]}`}, nil
}

func TestPipeline_RoleClientRoutingAndManifestRedaction(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "demo.c"), []byte("int verify(int value) { return value > 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	clients := map[string]*roleClient{}
	overrides := map[string]config.LLMRoleOverride{}
	for _, role := range config.LLMRoles {
		clients[role] = &roleClient{role: role}
		overrides[role] = config.LLMRoleOverride{Model: role + "-model"}
	}
	// This fixture exercises role routing with legacy candidate packs; strict
	// contract acceptance has separate end-to-end coverage.
	dir, err := pipeline.RunWithClients(config.Config{AllowUncontractedCases: true, Command: "run", Target: root, Mode: "llm", Focus: "tee", RunID: "role-routing", OutputDir: out, KnowledgeRoot: filepath.Join(out, "knowledge"), LLMModel: "global-model", LLMBaseURL: "https://user:never-persist@example.invalid/api?key=never-persist", LLMAPIKey: "never-persist", RoleOverrides: overrides}, pipeline.RoleClients{Planner: clients["planner"], Expert: clients["expert"], Challenger: clients["challenger"], Verifier: clients["verifier"], Arbiter: clients["arbiter"]})
	if err != nil {
		t.Fatal(err)
	}
	for role, client := range clients {
		if role != "arbiter" && client.calls == 0 {
			t.Errorf("%s client unused", role)
		}
	}
	for _, event := range readEvents(t, dir) {
		if event.Type != events.TypeLLMCallCompleted {
			continue
		}
		role := strings.TrimSuffix(event.Agent, "-001")
		if event.Model != role+"-model" {
			t.Errorf("%s recorded model %q", event.Agent, event.Model)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "00_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), "never-persist") {
		t.Fatal("credential leaked into manifest")
	}
	for role := range clients {
		if !strings.Contains(string(manifest), role+"-model") {
			t.Errorf("%s settings absent from manifest", role)
		}
	}
}
