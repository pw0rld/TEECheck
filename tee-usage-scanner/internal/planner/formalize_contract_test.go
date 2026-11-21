package planner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/contracts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func TestFormalizeContractBindsImmediatelyAndRecordsLead(t *testing.T) {
	cfg, state, observed, _, contract := closingContractFixture(t)
	result := formalizeContract(cfg, state, observed, nil, artifacts.RoundRecord{}, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "contract": contract}))
	if !result.OK {
		t.Fatal(result.Error)
	}
	if len(state.Contracts) != 1 || state.Contracts[0].Grounding != "source_bound" || state.Contracts[0].Scope.Commit != "abc" {
		t.Fatalf("unbound contract: %+v", state.Contracts)
	}
	bound := state.Contracts[0]
	if state.AuditLeads[0].State != artifacts.LeadStateFormalized || len(state.AuditLeads[0].ContractIDs) != 1 || state.AuditLeads[0].ContractIDs[0] != bound.InvariantID {
		t.Fatalf("lead was not formalized: %+v", state.AuditLeads[0])
	}
	var persisted artifacts.CaseInvariantV2
	if err := runfs.ReadJSON(filepath.Join(runfs.PlannerDir(cfg.RunDir), "contracts", bound.DefinitionHash+".json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.DefinitionHash != bound.DefinitionHash || len(persisted.Subjects) != 1 || len(persisted.EvidenceRefs) == 0 {
		t.Fatalf("wrong persisted contract: %+v", persisted)
	}
}

func TestFormalizeContractReportsInvalidDraftThenAcceptsCorrection(t *testing.T) {
	for _, mode := range []string{"missing preconditions", "bad query", "unread symbol", "unknown symbol", "unobserved reference"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, observed, _, valid := closingContractFixture(t)
			state.AuditLeads[0].State = artifacts.LeadStateOpen
			bad := valid
			switch mode {
			case "missing preconditions":
				bad.Preconditions = nil
			case "bad query":
				bad.VerificationQueries = []artifacts.ContractQuery{{Backend: "codeql", Operation: "unregistered"}}
			case "unread symbol":
				if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "unread.c"), []byte("int other(void) { return 1; }\n"), 0600); err != nil {
					t.Fatal(err)
				}
				bad.Subjects = append(append([]artifacts.ContractSubject(nil), valid.Subjects...), artifacts.ContractSubject{Path: "unread.c", Symbol: "other"})
			case "unknown symbol":
				bad.Subjects = append(append([]artifacts.ContractSubject(nil), valid.Subjects...), artifacts.ContractSubject{Path: "a.c", Symbol: "unknown"})
			case "unobserved reference":
				bad.EvidenceRefs = []artifacts.ContractEvidenceRef{{Kind: "observation", Ref: "obs:1:1:0:another-sample"}}
			}
			result := formalizeContract(cfg, state, observed, nil, artifacts.RoundRecord{}, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "contract": bad}))
			if result.OK || result.Error == "" || len(state.Contracts) != 0 || state.AuditLeads[0].State != artifacts.LeadStateOpen || len(state.AuditLeads[0].ContractIDs) != 0 {
				t.Fatalf("bad draft advanced state: result=%+v state=%+v", result, state)
			}
			files, err := filepath.Glob(filepath.Join(runfs.PlannerDir(cfg.RunDir), "contracts", "*.json"))
			if err != nil || len(files) != 0 {
				t.Fatalf("bad draft persisted a contract: %v %v", files, err)
			}
			result = formalizeContract(cfg, state, observed, nil, artifacts.RoundRecord{}, leadArgs(t, map[string]any{"lead_id": "lead-s2-001", "contract": valid}))
			if !result.OK || len(state.Contracts) != 1 || state.AuditLeads[0].State != artifacts.LeadStateFormalized {
				t.Fatalf("correction failed: %+v", result)
			}
		})
	}
}

type immediateContractClient struct {
	t      *testing.T
	calls  int
	refuse bool
}

func (client *immediateContractClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	client.calls++
	if client.calls == 1 {
		contract := closingTestContract()
		contract.EvidenceRefs = []artifacts.ContractEvidenceRef{{Kind: "observation", Ref: MakeObservationRef("reliable", 0, 1, 0, "")}}
		body := map[string]any{"actions": []any{
			map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 1}},
			map[string]any{"name": "open_audit_lead", "args": map[string]any{"security_question": "Does verify enforce the required input contract?", "target_symbol_ids": []string{"a.c::verify"}, "reason": []string{"Observed the verification decision."}, "reason_fact_refs": []string{MakeObservationRef("reliable", 0, 1, 0, "")}}},
			map[string]any{"name": "formalize_contract", "args": map[string]any{"lead_id": "lead-s0-001", "contract": contract}},
		}}
		data, err := json.Marshal(body)
		if err != nil {
			client.t.Fatal(err)
		}
		return llm.GenerateResponse{Text: string(data), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 100, TotalTokens: 200}}, nil
	}
	if client.calls == 2 {
		if !strings.Contains(req.Messages[0].Content, "formalized") {
			client.t.Fatalf("next round lost the formalized lead: %s", req.Messages[0].Content)
		}
		if client.refuse {
			return llm.GenerateResponse{}, errors.New("HTTP 502: flagged for possible cybersecurity risk")
		}
		return llm.GenerateResponse{Text: `{"actions":[{"name":"done","args":{"summary":"Contract recorded during investigation.","candidates":[]}}]}`, Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 100, TotalTokens: 200}}, nil
	}
	client.t.Fatalf("unexpected additional request %d", client.calls)
	return llm.GenerateResponse{}, nil
}

func TestPlannerRun_ImmediateContractSurvivesDoneOrPolicyRefusal(t *testing.T) {
	for _, refusal := range []bool{false, true} {
		name := "done"
		if refusal {
			name = "policy refusal"
		}
		t.Run(name, func(t *testing.T) {
			root, run := reliabilityFixture(t)
			if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{RunID: "reliable", Repository: artifacts.RepositoryCard{FileCount: 1}, Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityUnavailable}}); err != nil {
				t.Fatal(err)
			}
			client := &immediateContractClient{t: t, refuse: refusal}
			budget := NewDefaultBudget()
			budget.MaxReconRounds = 0
			result := Run(context.Background(), RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, Registry: actions.NewDefaultRegistryWithNav(), Client: client, Budget: budget})
			if client.calls != 2 {
				t.Fatalf("requests=%d want 2", client.calls)
			}
			if refusal {
				if result.Err == nil || result.Bundle.PlannerMeta.TerminationReason != "policy_refusal" {
					t.Fatalf("refusal not preserved: %v %+v", result.Err, result.Bundle.PlannerMeta)
				}
			} else if result.Err != nil || result.Bundle.PlannerMeta.TerminationReason != "llm_done" {
				t.Fatalf("run did not conclude: %v %+v", result.Err, result.Bundle.PlannerMeta)
			}
			if len(result.CasePacks) != 1 || len(result.CasePacks[0].CaseInvariants) != 1 {
				t.Fatalf("immediate contract lost after %s: %+v; errors=%+v", name, result.CasePacks, result.Bundle.Errors)
			}
			contract := result.CasePacks[0].CaseInvariants[0]
			if contract.Grounding != "source_bound" {
				t.Fatalf("grounding=%s", contract.Grounding)
			}
			if err := contracts.Validate(contract, contracts.BindingContext{RunDir: run, RepoRoot: root, Scope: contract.Scope}); err != nil {
				t.Fatalf("final contract cannot validate persisted same-round evidence: %v", err)
			}
			rows := closingRounds(t, run)
			if len(rows) < 1 || len(rows[0].Observations) != 3 || !rows[0].Observations[2].OK {
				t.Fatalf("same-round formalize failed: %+v", rows)
			}
			leads, err := contractLeads(RunConfig{RunID: "reliable", RunDir: run})
			if err != nil || leads["lead-s0-001"].State != artifacts.LeadStateFormalized {
				t.Fatalf("lead state was not persisted: %+v %v", leads, err)
			}
		})
	}
}
