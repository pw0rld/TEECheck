package planner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events/eventstest"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// The model follows the public action protocol so these tests exercise actual
// observations, lead creation, closing, source binding, and artifact writes.
type closingIntegrationClient struct {
	t        *testing.T
	requests []llm.GenerateRequest
	typed    bool
	noLead   bool
	refuse   bool
	badLead  bool
	readRef  string
}

func (c *closingIntegrationClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.t.Helper()
	c.requests = append(c.requests, req)
	usage := llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}
	respond := func(v any) (llm.GenerateResponse, error) {
		body, err := json.Marshal(v)
		if err != nil {
			c.t.Fatal(err)
		}
		return llm.GenerateResponse{Text: string(body), Usage: usage}, nil
	}
	step := len(c.requests)
	if step == 1 {
		return respond(map[string]any{"actions": []any{
			map[string]any{"name": "get_repository_card", "args": map[string]any{}},
			map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
			map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 4}},
		}})
	}
	if step == 2 && !c.noLead {
		match := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
		if len(match) != 2 {
			c.t.Fatalf("real read_file reference missing from next request: %s", req.Messages[0].Content)
		}
		c.readRef = match[1]
		return respond(map[string]any{"actions": []any{map[string]any{
			"name": "open_audit_lead", "args": map[string]any{
				"security_question": "Does verify enforce its input contract?",
				"target_symbol_ids": []string{"a.c::verify"},
				"reason":            []string{"The observed source returns a verification decision."},
				"reason_fact_refs":  []string{c.readRef},
			},
		}}})
	}
	if (step == 3 && !c.noLead) || (step == 2 && c.noLead) {
		args := map[string]any{
			"summary": "Review the input verification obligation.",
			"candidates": []any{map[string]any{
				"id": "candidate-verify", "kind": "guard", "priority": "high",
				"paths": []string{"a.c"}, "symbols": []string{"verify"},
				"why_selected": []string{"Verification returns a decision without checking the input contract."},
			}},
		}
		if c.typed {
			args["case_invariants"] = []artifacts.CaseInvariantV2{closingTestContract()}
		}
		return respond(map[string]any{"actions": []any{map[string]any{"name": "done", "args": args}}})
	}
	if step != 4 || c.typed || c.noLead {
		c.t.Fatalf("unexpected model call %d (typed=%v, noLead=%v)", step, c.typed, c.noLead)
	}
	if c.refuse {
		return llm.GenerateResponse{}, errors.New("upstream HTTP 502: flagged for possible cybersecurity risk")
	}
	var input formalizationInput
	if err := json.Unmarshal([]byte(req.Messages[0].Content), &input); err != nil {
		c.t.Fatalf("closing input must be structured: %v", err)
	}
	if len(input.Candidates) != 1 || input.Candidates[0].Index != 0 || input.Candidates[0].Candidate.ID != "candidate-verify" {
		c.t.Fatalf("closing request lost the candidate: %+v", input)
	}
	if len(input.Sources) != 1 || input.Sources[0].Ref != c.readRef || !strings.Contains(input.Sources[0].Text, "int verify(void)") {
		c.t.Fatalf("closing request not grounded in the observed source: %+v", input.Sources)
	}
	if len(input.Candidates[0].Leads) != 1 || input.Candidates[0].Leads[0].LeadID != "lead-s0-001" {
		c.t.Fatalf("closing request lost the current lead: %+v", input.Candidates[0].Leads)
	}
	if req.MaxOutputTokens <= 0 || req.MaxOutputTokens > config.DefaultLLMMaxTokens {
		c.t.Fatalf("unbounded closing reply: %d", req.MaxOutputTokens)
	}
	contract := closingTestContract()
	if c.badLead {
		contract.LeadRef = "invented-lead"
	}
	return respond(map[string]any{"formalizations": []any{map[string]any{
		"candidate_index":  0,
		"case_invariants":  []artifacts.CaseInvariantV2{contract},
		"missing_evidence": []string{},
	}}})
}

func closingTestContract() artifacts.CaseInvariantV2 {
	return artifacts.CaseInvariantV2{
		LeadRef:             "lead-s0-001",
		Subjects:            []artifacts.ContractSubject{{Path: "a.c", Symbol: "verify"}},
		Preconditions:       []string{"verify is used to decide whether an input is accepted"},
		RequiredProperty:    artifacts.ContractProperty{Kind: "guard", Statement: "verify must check the input contract before accepting it"},
		SecurityEffect:      "input acceptance decision",
		VerificationQueries: []artifacts.ContractQuery{},
	}
}

func runClosingIntegration(t *testing.T, client *closingIntegrationClient) (RunResult, string, *eventstest.Harness) {
	t.Helper()
	root, run := reliabilityFixture(t)
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		RunID: "reliable", Repository: artifacts.RepositoryCard{FileCount: 1},
		Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityUnavailable},
	}); err != nil {
		t.Fatal(err)
	}
	h := eventstest.New(t)
	client.t = t
	result := Run(context.Background(), RunConfig{
		RunID: "reliable", RepoRoot: root, RunDir: run, Client: client,
		Registry: actions.NewDefaultRegistryWithNav(), Budget: NewDefaultBudget(),
		Events: h.Recorder, Blobs: h.Blobs, Model: "test-model",
	})
	return result, run, h
}

func TestPlannerRun_ClosingFormalizesLegacyCandidate(t *testing.T) {
	client := &closingIntegrationClient{}
	result, run, h := runClosingIntegration(t, client)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.Bundle.PlannerMeta.TerminationReason != "llm_done" || len(client.requests) != 4 {
		t.Fatalf("closing did not complete: termination=%s requests=%d", result.Bundle.PlannerMeta.TerminationReason, len(client.requests))
	}
	assertClosingContract(t, result)
	assertClosingAccounting(t, result, run, h, 4)
	rows := closingRounds(t, run)
	var read artifacts.RoundObservation
	for _, observation := range rows[0].Observations {
		if observation.Name == "read_file" {
			read = observation
		}
	}
	wantRef := MakeObservationRef("reliable", 0, 1, read.ActionIndex, read.OutputBlob)
	if read.Ref != wantRef || read.Ref != client.readRef {
		t.Fatalf("contract did not originate from a real observation: got=%s want=%s", read.Ref, wantRef)
	}
	contract := result.CasePacks[0].CaseInvariants[0]
	found := false
	for _, ref := range contract.EvidenceRefs {
		if ref.Kind == "observation" && ref.Ref == read.Ref {
			found = true
		}
	}
	if !found {
		t.Fatalf("bound contract lost its observed source reference: %+v", contract.EvidenceRefs)
	}
}

func TestPlannerRun_ClosingKeepsExplicitContractWithoutExtraCall(t *testing.T) {
	client := &closingIntegrationClient{typed: true}
	result, run, h := runClosingIntegration(t, client)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(client.requests) != 3 {
		t.Fatalf("explicit contract triggered a redundant closing call: %d", len(client.requests))
	}
	assertClosingContract(t, result)
	assertClosingAccounting(t, result, run, h, 3)
}

func TestPlannerRun_ClosingPolicyRefusalKeepsCandidateAndLead(t *testing.T) {
	client := &closingIntegrationClient{refuse: true}
	result, run, h := runClosingIntegration(t, client)
	if result.Err == nil || result.Bundle.PlannerMeta.TerminationReason != "policy_refusal" {
		t.Fatalf("expected explicit policy failure, got %v / %+v", result.Err, result.Bundle.PlannerMeta)
	}
	if len(client.requests) != 4 || len(result.Bundle.Candidates) != 1 || len(result.CasePacks) != 1 || len(result.CasePacks[0].CaseInvariants) != 0 {
		t.Fatalf("refusal retried or lost legacy evidence: requests=%d candidates=%d packs=%+v", len(client.requests), len(result.Bundle.Candidates), result.CasePacks)
	}
	leads, err := os.ReadFile(runfs.AuditLeadsPath(run))
	if err != nil || !strings.Contains(string(leads), "lead-s0-001") {
		t.Fatalf("original lead lost: %s, %v", leads, err)
	}
	found := false
	for _, problem := range result.Bundle.Errors {
		if problem.Action == "formalize_candidates" && strings.Contains(problem.Error, "flagged") {
			found = true
		}
	}
	if !found || !strings.Contains(strings.Join(result.Bundle.CoverageGaps, " "), "upstream policy refusal") {
		t.Fatalf("refusal lacks a visible diagnostic: %+v", result.Bundle)
	}
	assertClosingAccounting(t, result, run, h, 3)
}

func TestPlannerRun_ClosingSkipsCandidateWithoutLead(t *testing.T) {
	client := &closingIntegrationClient{noLead: true}
	result, _, _ := runClosingIntegration(t, client)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(client.requests) != 2 || len(result.CasePacks) != 1 || len(result.CasePacks[0].CaseInvariants) != 0 {
		t.Fatalf("ungrounded candidate was formalized: requests=%d packs=%+v", len(client.requests), result.CasePacks)
	}
	if !strings.Contains(strings.Join(result.Bundle.CoverageGaps, " "), "missing a matching current-sample audit lead") {
		t.Fatalf("missing lead was not explained: %+v", result.Bundle.CoverageGaps)
	}
}

func TestPlannerRun_ClosingRejectsInventedLead(t *testing.T) {
	client := &closingIntegrationClient{badLead: true}
	result, _, _ := runClosingIntegration(t, client)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(result.CasePacks) != 1 || len(result.CasePacks[0].CaseInvariants) != 0 || len(result.Bundle.Candidates) != 1 {
		t.Fatalf("invented lead bypassed grounding: %+v", result.CasePacks)
	}
	found := false
	for _, problem := range result.Bundle.Errors {
		if strings.Contains(problem.Error, "matching current-sample lead") {
			found = true
		}
	}
	if !found {
		t.Fatalf("invalid formalization was not diagnosed: %+v", result.Bundle.Errors)
	}
}

func assertClosingContract(t *testing.T, result RunResult) {
	t.Helper()
	if len(result.Bundle.Candidates) != 1 || len(result.CasePacks) != 1 {
		t.Fatalf("closing duplicated or dropped original candidate: candidates=%d packs=%+v", len(result.Bundle.Candidates), result.CasePacks)
	}
	pack := result.CasePacks[0]
	if !pack.ContractRequired || strings.HasPrefix(pack.CaseID, "contract:") || len(pack.CaseInvariants) != 1 {
		t.Fatalf("contract must attach to the original candidate pack: %+v", pack)
	}
	c := pack.CaseInvariants[0]
	if c.Grounding != "source_bound" || c.LeadRef != "lead-s0-001" || c.DefinitionHash == "" || len(c.VerificationQueries) != 0 {
		t.Fatalf("source-only contract was not bound: %+v", c)
	}
}

func closingRounds(t *testing.T, run string) []artifacts.RoundRecord {
	t.Helper()
	f, err := os.Open(runfs.RoundsLogPath(run))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rounds []artifacts.RoundRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var round artifacts.RoundRecord
		if err := json.Unmarshal(scanner.Bytes(), &round); err != nil {
			t.Fatal(err)
		}
		rounds = append(rounds, round)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rounds
}

func assertClosingAccounting(t *testing.T, result RunResult, run string, h *eventstest.Harness, successfulCalls int) {
	t.Helper()
	var roundTokens, eventTokens int
	rounds := closingRounds(t, run)
	for _, round := range rounds {
		roundTokens += round.TokensIn + round.TokensOut
	}
	for _, event := range h.Events() {
		if event.Type == events.TypeLLMCallCompleted {
			eventTokens += event.TokensIn + event.TokensOut
		}
	}
	want := successfulCalls * 120
	if result.Bundle.PlannerMeta.TokensUsed != want || roundTokens != want || eventTokens != want {
		t.Fatalf("closing usage disagrees: bundle=%d rounds=%d events=%d want=%d", result.Bundle.PlannerMeta.TokensUsed, roundTokens, eventTokens, want)
	}
	if len(rounds) != result.Bundle.PlannerMeta.RoundsUsed {
		t.Fatalf("closing changed round accounting: saved=%d bundle=%d", len(rounds), result.Bundle.PlannerMeta.RoundsUsed)
	}
	var saved artifacts.EvidenceBundle
	if err := runfs.ReadJSON(runfs.EvidenceBundlePath(run), &saved); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved.PlannerMeta, result.Bundle.PlannerMeta) {
		t.Fatalf("persisted bundle differs from returned accounting: saved=%+v returned=%+v", saved.PlannerMeta, result.Bundle.PlannerMeta)
	}
}
