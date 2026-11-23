package planner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner/actions"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

func closingContractFixture(t *testing.T) (RunConfig, *PlannerState, ObservationSet, formalizationCandidate, artifacts.CaseInvariantV2) {
	t.Helper()
	root, run := reliabilityFixture(t)
	budget := NewDefaultBudget()
	budget.Start()
	cfg := RunConfig{RunID: "reliable", RepoRoot: root, RunDir: run, SampleIndex: 2, Budget: budget}
	state := NewState(cfg.RunID)
	const ref = "obs:2:1:0:source"
	state.AuditLeads = []artifacts.AuditLead{{RunID: cfg.RunID, SampleIndex: cfg.SampleIndex, LeadID: "lead-s2-001", TargetSymbolIDs: []artifacts.SymbolID{"a.c::verify"}, ReasonFactRefs: []string{ref}}}
	state.Rounds = []artifacts.RoundRecord{{Actions: []artifacts.RoundAction{{Name: "read_file", Args: json.RawMessage(`{"path":"a.c"}`)}}, Observations: []artifacts.RoundObservation{{Name: "read_file", OK: true, Ref: ref, ActionIndex: 0, Output: "1: int verify(void) { return 1; }\n"}}}}
	observed := ObservationSet{}
	observed.Record(ref, true)
	candidate := formalizationCandidate{Index: 0, Candidate: artifacts.Candidate{ID: "candidate-1", Paths: []string{"a.c"}, Symbols: []string{"verify"}}, Leads: state.AuditLeads}
	contract := artifacts.CaseInvariantV2{LeadRef: "lead-s2-001", Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "verify"}}, Preconditions: []string{"the function is called"}, RequiredProperty: artifacts.ContractProperty{Kind: "guard", Statement: "the function returns a validated result"}, SecurityEffect: "the caller's validation decision"}
	return cfg, state, observed, candidate, contract
}

func closingDone(candidate artifacts.Candidate) *actions.DonePayload {
	paths, symbols := make([]any, len(candidate.Paths)), make([]any, len(candidate.Symbols))
	for i, path := range candidate.Paths {
		paths[i] = path
	}
	for i, symbol := range candidate.Symbols {
		symbols[i] = symbol
	}
	return &actions.DonePayload{Candidates: []map[string]any{{"id": candidate.ID, "paths": paths, "symbols": symbols}}}
}

func TestClosingCandidateTargetForms(t *testing.T) {
	lead := artifacts.AuditLead{TargetSymbolIDs: []artifacts.SymbolID{"cpp:a.c:1:verify()"}}
	contract := artifacts.CaseInvariantV2{Subjects: []artifacts.ContractSubject{{Path: "a.c", Symbol: "verify"}}}
	for _, symbols := range [][]string{nil, {"verify"}, {"a.c::verify"}, {"cpp:a.c:1:verify()"}, {"wrong"}} {
		t.Run(strings.Join(symbols, ","), func(t *testing.T) {
			candidate := artifacts.Candidate{Paths: []string{"a.c"}, Symbols: symbols}
			want := len(symbols) == 0 || symbols[0] != "wrong"
			if got := candidateSharesLead(candidate, lead); got != want {
				t.Errorf("candidateSharesLead=%v, want %v", got, want)
			}
			if got := contractTargetsCandidate(contract, candidate); got != want {
				t.Errorf("contractTargetsCandidate=%v, want %v", got, want)
			}
		})
	}
}

func TestGroundClosingContractRejectsUnobservedOrMismatchedClaims(t *testing.T) {
	for _, mode := range []string{"unknown subject", "unread source", "other sample observation", "wrong lead", "other candidate target", "source outside observed window"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, observed, candidate, contract := closingContractFixture(t)
			sources := formalizationSources(state, observed)
			switch mode {
			case "unknown subject":
				contract.Subjects = append(contract.Subjects, artifacts.ContractSubject{Path: "a.c", Symbol: "missing"})
			case "unread source":
				if err := os.WriteFile(filepath.Join(cfg.RepoRoot, "unread.c"), []byte("int consumer(void) { return 1; }\n"), 0600); err != nil {
					t.Fatal(err)
				}
				contract.Subjects = append(contract.Subjects, artifacts.ContractSubject{Path: "unread.c", Symbol: "consumer"})
			case "other sample observation":
				contract.EvidenceRefs = []artifacts.ContractEvidenceRef{{Kind: "observation", Ref: "obs:1:1:0:source"}}
			case "wrong lead":
				contract.LeadRef = "lead-s1-001"
			case "other candidate target":
				candidate.Candidate.Symbols = []string{"other"}
			case "source outside observed window":
				contract.EvidenceRefs = []artifacts.ContractEvidenceRef{{Kind: "source", Path: "a.c", StartLine: 1, EndLine: 2}}
			}
			if err := groundClosingContract(&contract, candidate, sources, cfg.RepoRoot); err == nil {
				t.Fatal("unobserved or mismatched closing contract was accepted")
			}
		})
	}
}

func TestGroundClosingContractAddsObservedWitnesses(t *testing.T) {
	cfg, state, observed, candidate, contract := closingContractFixture(t)
	if err := groundClosingContract(&contract, candidate, formalizationSources(state, observed), cfg.RepoRoot); err != nil {
		t.Fatal(err)
	}
	var source, observation bool
	for _, ref := range contract.EvidenceRefs {
		source = source || (ref.Kind == "source" && ref.Path == "a.c" && ref.Symbol == "verify" && ref.StartLine == 1 && ref.EndLine == 1)
		observation = observation || (ref.Kind == "observation" && ref.Ref == "obs:2:1:0:source")
	}
	if !source || !observation {
		t.Fatalf("contract lost source/observation lineage: %+v", contract.EvidenceRefs)
	}
}

func TestFormalizationSourcesUsesOnlySuccessfulCurrentSampleReads(t *testing.T) {
	_, state, observed, _, _ := closingContractFixture(t)
	for _, mode := range []string{"previous sample", "failed read", "navigation action", "wrong action index", "invalid args"} {
		ref := "obs:" + mode
		action := artifacts.RoundAction{Name: "read_file", Args: json.RawMessage(`{"path":"unseen.c"}`)}
		observation := artifacts.RoundObservation{Name: "read_file", OK: true, Ref: ref, ActionIndex: 0, Output: "1: int unseen(void) { return 0; }\n"}
		switch mode {
		case "previous sample":
			// Persisted observations from another sample are not in this
			// sample's live ObservationSet even when they succeeded.
		case "failed read":
			observed.Record(ref, false)
			observation.OK = false
		case "navigation action":
			observed.Record(ref, true)
			action.Name, observation.Name = "get_function_card", "get_function_card"
		case "wrong action index":
			observed.Record(ref, true)
			observation.ActionIndex = 1
		case "invalid args":
			observed.Record(ref, true)
			action.Args = json.RawMessage(`{`)
		}
		state.Rounds = append(state.Rounds, artifacts.RoundRecord{Actions: []artifacts.RoundAction{action}, Observations: []artifacts.RoundObservation{observation}})
	}
	sources := formalizationSources(state, observed)
	if len(sources) != 1 || sources[0].Ref != "obs:2:1:0:source" || sources[0].Path != "a.c" {
		t.Fatalf("non-source or other-sample observations entered the request: %+v", sources)
	}
}

func TestFormalizationSourcesTruncatesAtWholeNumberedLines(t *testing.T) {
	_, state, observed, _, _ := closingContractFixture(t)
	first := "10: " + strings.Repeat("界", 900) + "\n"
	state.Rounds[0].Observations[0].Output = first + "11: " + strings.Repeat("x", 400) + "\n12: unseen tail\n"
	sources := formalizationSources(state, observed)
	if len(sources) != 1 || sources[0].Start != 10 || sources[0].End != 10 || sources[0].Text != first {
		t.Fatalf("source did not stop before the first whole line exceeding the window: %+v", sources)
	}
	state.Rounds[0].Observations[0].Output = "10: first\n12: discontinuity\n13: later\n"
	sources = formalizationSources(state, observed)
	if len(sources) != 1 || sources[0].End != 10 || sources[0].Text != "10: first\n" {
		t.Fatalf("discontinuous source range was accepted: %+v", sources)
	}
}

func TestFormalizationSourcesDropsIncompleteTrailingLine(t *testing.T) {
	for _, output := range []string{
		"1: int verify(void) {\n2: return partial",
		"1: int verify(void) {\n2: return partial\n... (truncated at 44 bytes of 100; the full body was not stored)",
	} {
		_, state, observed, _, _ := closingContractFixture(t)
		state.Rounds[0].Observations[0].Output = output
		state.Rounds[0].Observations[0].Truncated = true
		sources := formalizationSources(state, observed)
		if len(sources) != 1 || sources[0].End != 1 || sources[0].Text != "1: int verify(void) {\n" {
			t.Errorf("a partial line became observed source: %+v", sources)
		}
	}
}

func TestFormalizeCandidatesDoesNotDispatchWithoutBudgetOrContext(t *testing.T) {
	for _, mode := range []string{"token budget", "cancelled context", "wall clock"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, observed, candidate, _ := closingContractFixture(t)
			ctx := context.Background()
			switch mode {
			case "token budget":
				cfg.Budget.MaxTokens = 1
			case "cancelled context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "wall clock":
				cfg.Budget.WallClock = 1
			}
			calls := 0
			got, _, gaps, _ := formalizeCandidates(ctx, cfg, closingDone(candidate.Candidate), state, observed, func(string, string) (llm.GenerateResponse, error) {
				calls++
				return llm.GenerateResponse{}, nil
			})
			if calls != 0 || len(got) != 0 || len(gaps) == 0 {
				t.Fatalf("unavailable budget/context dispatched or lost gap: calls=%d contracts=%v gaps=%v", calls, got, gaps)
			}
		})
	}
}

func TestFormalizeCandidatesDoesNotBorrowAnotherSamplesLead(t *testing.T) {
	cfg, state, observed, candidate, _ := closingContractFixture(t)
	state.AuditLeads[0].SampleIndex = 1
	calls := 0
	got, _, gaps, err := formalizeCandidates(context.Background(), cfg, closingDone(candidate.Candidate), state, observed, func(string, string) (llm.GenerateResponse, error) {
		calls++
		return llm.GenerateResponse{}, nil
	})
	if err != nil || calls != 0 || len(got) != 0 || len(gaps) == 0 {
		t.Fatalf("other-sample lead was accepted: calls=%d contracts=%v gaps=%v err=%v", calls, got, gaps, err)
	}
}

func TestFormalizeCandidatesMissingReplyRetainsGap(t *testing.T) {
	for _, reply := range []string{`{}`, `{"formalizations":[]}`, `{"formalizations":[{"candidate_index":0,"case_invariants":[]}]}`} {
		t.Run(reply, func(t *testing.T) {
			cfg, state, observed, candidate, _ := closingContractFixture(t)
			calls := 0
			done := closingDone(candidate.Candidate)
			got, problems, gaps, err := formalizeCandidates(context.Background(), cfg, done, state, observed, func(string, string) (llm.GenerateResponse, error) {
				calls++
				return llm.GenerateResponse{Text: reply}, nil
			})
			if err != nil || calls != 1 || len(got) != 0 || len(problems) != 0 || len(gaps) == 0 || len(done.Candidates) != 1 || len(state.AuditLeads) != 1 {
				t.Fatalf("empty formalization lost candidate, lead, or gap: calls=%d contracts=%v problems=%v gaps=%v err=%v", calls, got, problems, gaps, err)
			}
		})
	}
}

type scriptedStrictClient struct {
	t          *testing.T
	stepFn     func(call int, req llm.GenerateRequest) (any, string)
	calls      int
	lastPrompt string
}

func (c *scriptedStrictClient) Generate(_ context.Context, req llm.GenerateRequest) (llm.GenerateResponse, error) {
	c.t.Helper()
	c.calls++
	c.lastPrompt = req.Messages[0].Content
	obj, rawText := c.stepFn(c.calls, req)
	if rawText != "" {
		return llm.GenerateResponse{Text: rawText, Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
	}
	body, err := json.Marshal(obj)
	if err != nil {
		c.t.Fatal(err)
	}
	return llm.GenerateResponse{Text: string(body), Usage: llm.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}}, nil
}

func setupStrictExitRun(t *testing.T, maxInvRounds int) (string, string, RunConfig) {
	t.Helper()
	root, run := reliabilityFixture(t)
	if err := runfs.WriteJSON(runfs.ProjectMapPath(run), artifacts.ProjectMap{
		RunID:        "reliable",
		Repository:   artifacts.RepositoryCard{FileCount: 1},
		Capabilities: artifacts.IndexCapabilities{Symbols: artifacts.CapabilityUnavailable},
	}); err != nil {
		t.Fatal(err)
	}
	b := NewDefaultBudget()
	b.MaxReconRounds = 1
	b.MaxRounds = maxInvRounds
	cfg := RunConfig{
		RunID:              "reliable",
		RepoRoot:           root,
		RunDir:             run,
		Registry:           actions.NewDefaultRegistryWithNav(),
		Budget:             b,
		StrictContractExit: true,
	}
	return root, run, cfg
}

// Regression 1: Invalid contract in `done` (matching lead_ref & subjects, missing
// required_property) MUST NOT bypass strict exit.
func TestStrictContractExit_InvalidContractInDoneRejectedThenRecoveredAndExhaustionMarksIncomplete(t *testing.T) {
	t.Run("rejected_then_recovered_next_round", func(t *testing.T) {
		_, run, cfg := setupStrictExitRun(t, 4)
		var readRef string
		client := &scriptedStrictClient{t: t}
		client.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
			switch call {
			case 1:
				return map[string]any{"actions": []any{
					map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
					map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 4}},
				}}, ""
			case 2:
				m := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
				if len(m) != 2 {
					t.Fatalf("missing read_file ref in prompt: %s", req.Messages[0].Content)
				}
				readRef = m[1]
				return map[string]any{"actions": []any{
					map[string]any{"name": "open_audit_lead", "args": map[string]any{
						"security_question": "Does verify check input?",
						"target_symbol_ids": []string{"a.c::verify"},
						"reason":            []string{"Observed unconditional return."},
						"reason_fact_refs":  []string{readRef},
					}},
				}}, ""
			case 3:
				return map[string]any{"actions": []any{
					map[string]any{"name": "done", "args": map[string]any{
						"summary":    "attempted invalid draft shortcut",
						"candidates": []any{},
						"case_invariants": []any{map[string]any{
							"lead_ref": "lead-s0-001",
							"subjects": []any{map[string]any{"path": "a.c", "symbol": "verify"}},
						}},
					}},
				}}, ""
			case 4:
				if !strings.Contains(req.Messages[0].Content, "done refused") {
					t.Fatalf("round 4 did not surface done refusal diagnostic: %s", req.Messages[0].Content)
				}
				valid := closingTestContract()
				return map[string]any{"actions": []any{
					map[string]any{"name": "done", "args": map[string]any{
						"summary":         "corrected valid contract",
						"candidates":      []any{},
						"case_invariants": []artifacts.CaseInvariantV2{valid},
					}},
				}}, ""
			default:
				t.Fatalf("unexpected call %d", call)
				return nil, ""
			}
		}
		cfg.Client = client
		res := Run(context.Background(), cfg)
		if res.Err != nil {
			t.Fatal(res.Err)
		}
		if client.calls != 4 || res.Bundle.PlannerMeta.TerminationReason != "llm_done" || len(res.CasePacks) != 1 {
			t.Fatalf("calls=%d termination=%s packs=%d", client.calls, res.Bundle.PlannerMeta.TerminationReason, len(res.CasePacks))
		}
		cp, err := InspectCheckpoint(run, cfg.RepoRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(cp.State.AuditLeads) != 1 || cp.State.AuditLeads[0].State != artifacts.LeadStateFormalized {
			t.Fatalf("checkpoint lead state was not updated to formalized: %+v", cp.State.AuditLeads)
		}
	})

	t.Run("budget_exhaustion_marks_incomplete_never_llm_done", func(t *testing.T) {
		_, run, cfg := setupStrictExitRun(t, 2)
		client := &scriptedStrictClient{t: t}
		client.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
			switch call {
			case 1:
				return map[string]any{"actions": []any{
					map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
					map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 4}},
				}}, ""
			case 2:
				m := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
				return map[string]any{"actions": []any{
					map[string]any{"name": "open_audit_lead", "args": map[string]any{
						"security_question": "Does verify check input?",
						"target_symbol_ids": []string{"a.c::verify"},
						"reason":            []string{"Observed unconditional return."},
						"reason_fact_refs":  []string{m[1]},
					}},
				}}, ""
			case 3:
				return map[string]any{"actions": []any{
					map[string]any{"name": "done", "args": map[string]any{
						"summary":    "invalid contract on final round",
						"candidates": []any{},
						"case_invariants": []any{map[string]any{
							"lead_ref": "lead-s0-001",
							"subjects": []any{map[string]any{"path": "a.c", "symbol": "verify"}},
						}},
					}},
				}}, ""
			default:
				t.Fatalf("unexpected call %d", call)
				return nil, ""
			}
		}
		cfg.Client = client
		res := Run(context.Background(), cfg)
		if res.Err != nil {
			t.Fatal(res.Err)
		}
		if len(res.CasePacks) != 0 {
			t.Fatalf("invalid contract produced CasePacks: %+v", res.CasePacks)
		}
		if res.Bundle.PlannerMeta.TerminationReason != "unresolved_leads_incomplete" {
			t.Fatalf("TerminationReason = %q, want unresolved_leads_incomplete", res.Bundle.PlannerMeta.TerminationReason)
		}
		var ledger artifacts.CoverageLedger
		if err := runfs.ReadJSON(runfs.CoverageLedgerPath(run), &ledger); err != nil {
			t.Fatal(err)
		}
		if len(ledger.BySample) != 1 || ledger.BySample[0].ReconStatus != reconStatusIncomplete {
			t.Fatalf("coverage ledger must mark sample incomplete when lead stays open: %+v", ledger.BySample)
		}
		cp, err := InspectCheckpoint(run, cfg.RepoRoot)
		if err != nil {
			t.Fatal(err)
		}
		if cp.TerminationReason != "unresolved_leads_incomplete" || cp.State.AuditLeads[0].State != artifacts.LeadStateOpen {
			t.Fatalf("checkpoint did not persist final incomplete state: reason=%s leads=%+v", cp.TerminationReason, cp.State.AuditLeads)
		}
	})
}

// Regression 2: Empty or malformed closing formalization reply must reject `done`
// while rounds remain and mark incomplete if budget runs out.
func TestStrictContractExit_EmptyOrMalformedClosingFormalizationRejectedAndNeverReportsLLMDone(t *testing.T) {
	for _, badClosingReply := range []string{`{}`, `not-valid-json-at-all`} {
		t.Run(badClosingReply, func(t *testing.T) {
			_, run, cfg := setupStrictExitRun(t, 3)
			client := &scriptedStrictClient{t: t}
			client.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
				switch call {
				case 1:
					return map[string]any{"actions": []any{
						map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
						map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 4}},
					}}, ""
				case 2:
					m := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
					return map[string]any{"actions": []any{
						map[string]any{"name": "open_audit_lead", "args": map[string]any{
							"security_question": "Does verify check input?",
							"target_symbol_ids": []string{"a.c::verify"},
							"reason":            []string{"Observed unconditional return."},
							"reason_fact_refs":  []string{m[1]},
						}},
					}}, ""
				case 3, 5:
					return map[string]any{"actions": []any{
						map[string]any{"name": "done", "args": map[string]any{
							"summary": "candidate needing closing formalization",
							"candidates": []any{map[string]any{
								"id": "cand-verify", "kind": "guard", "priority": "high",
								"paths": []string{"a.c"}, "symbols": []string{"verify"},
								"why_selected": []string{"unconditional return"},
							}},
						}},
					}}, ""
				case 4, 6:
					return nil, badClosingReply
				default:
					t.Fatalf("unexpected call %d", call)
					return nil, ""
				}
			}
			cfg.Client = client
			res := Run(context.Background(), cfg)
			if res.Err != nil {
				t.Fatal(res.Err)
			}
			if client.calls != 6 {
				t.Fatalf("calls = %d, want 6", client.calls)
			}
			if len(res.CasePacks) != 0 {
				t.Fatalf("uncontracted candidate leaked into CasePacks: %+v", res.CasePacks)
			}
			if res.Bundle.PlannerMeta.TerminationReason != "unresolved_leads_incomplete" {
				t.Fatalf("TerminationReason = %q, want unresolved_leads_incomplete", res.Bundle.PlannerMeta.TerminationReason)
			}
			var ledger artifacts.CoverageLedger
			if err := runfs.ReadJSON(runfs.CoverageLedgerPath(run), &ledger); err != nil {
				t.Fatal(err)
			}
			if len(ledger.BySample) != 1 || ledger.BySample[0].ReconStatus != reconStatusIncomplete {
				t.Fatalf("coverage ledger must be incomplete: %+v", ledger.BySample)
			}
			cp, err := InspectCheckpoint(run, cfg.RepoRoot)
			if err != nil {
				t.Fatal(err)
			}
			if cp.TerminationReason != "unresolved_leads_incomplete" || cp.State.AuditLeads[0].State != artifacts.LeadStateOpen {
				t.Fatalf("checkpoint mismatch: reason=%s leads=%+v", cp.TerminationReason, cp.State.AuditLeads)
			}
		})
	}
}

// Regression 3: Two open leads on the same function `a.c::verify`; when `done`
// resolves only lead-s0-001, `done` MUST be refused while preserving lead-s0-001
// as `formalized`, and succeed once lead-s0-002 is resolved next round.
func TestStrictContractExit_TwoLeadsSameFunctionRefusesDoneUntilBothResolved(t *testing.T) {
	_, run, cfg := setupStrictExitRun(t, 4)
	var readRef string
	client := &scriptedStrictClient{t: t}
	client.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
		switch call {
		case 1:
			return map[string]any{"actions": []any{
				map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
				map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 4}},
			}}, ""
		case 2:
			m := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
			readRef = m[1]
			return map[string]any{"actions": []any{
				map[string]any{"name": "open_audit_lead", "args": map[string]any{
					"security_question": "Does verify validate caller authority?",
					"target_symbol_ids": []string{"a.c::verify"},
					"reason":            []string{"Question 1 on verify."},
					"reason_fact_refs":  []string{readRef},
				}},
				map[string]any{"name": "open_audit_lead", "args": map[string]any{
					"security_question": "Does verify prevent state rollback?",
					"target_symbol_ids": []string{"a.c::verify"},
					"reason":            []string{"Question 2 on verify."},
					"reason_fact_refs":  []string{readRef},
				}},
			}}, ""
		case 3:
			onlyFirst := closingTestContract()
			onlyFirst.LeadRef = "lead-s0-001"
			return map[string]any{"actions": []any{
				map[string]any{"name": "done", "args": map[string]any{
					"summary":         "resolved only first lead",
					"candidates":      []any{},
					"case_invariants": []artifacts.CaseInvariantV2{onlyFirst},
				}},
			}}, ""
		case 4:
			if !strings.Contains(req.Messages[0].Content, "lead-s0-002") || !strings.Contains(req.Messages[0].Content, "done refused") {
				t.Fatalf("round 4 prompt must report lead-s0-002 still unresolved: %s", req.Messages[0].Content)
			}
			return map[string]any{"actions": []any{
				map[string]any{"name": "close_lead", "args": map[string]any{
					"lead_id":   "lead-s0-002",
					"reason":    "Stateless helper holds no rollback epoch.",
					"fact_refs": []string{readRef},
				}},
				map[string]any{"name": "done", "args": map[string]any{
					"summary":    "both leads resolved",
					"candidates": []any{},
				}},
			}}, ""
		default:
			t.Fatalf("unexpected call %d", call)
			return nil, ""
		}
	}
	cfg.Client = client
	res := Run(context.Background(), cfg)
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if client.calls != 4 || res.Bundle.PlannerMeta.TerminationReason != "llm_done" {
		t.Fatalf("calls=%d termination=%s", client.calls, res.Bundle.PlannerMeta.TerminationReason)
	}
	if len(res.CasePacks) != 1 || len(res.CasePacks[0].CaseInvariants) != 1 || res.CasePacks[0].CaseInvariants[0].LeadRef != "lead-s0-001" {
		t.Fatalf("expected 1 contracted pack for lead-s0-001, got %+v", res.CasePacks)
	}
	var ledger artifacts.CoverageLedger
	if err := runfs.ReadJSON(runfs.CoverageLedgerPath(run), &ledger); err != nil {
		t.Fatal(err)
	}
	if len(ledger.BySample) != 1 || ledger.BySample[0].ReconStatus != reconStatusSatisfied {
		t.Fatalf("expected satisfied coverage ledger once both leads resolved, got %+v", ledger.BySample)
	}
	cp, err := InspectCheckpoint(run, cfg.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.State.AuditLeads) != 2 ||
		cp.State.AuditLeads[0].State != artifacts.LeadStateFormalized ||
		cp.State.AuditLeads[1].State != artifacts.LeadStateClosed {
		t.Fatalf("checkpoint leads mismatch: %+v", cp.State.AuditLeads)
	}
}

// Regression 4 (Codex Review #4): After a partial read (lines 1..5 of a 25-line
// function), an already-accepted contract from `formalize_contract` (whose bound
// subject spans lines 1..25) MUST survive a subsequent empty `done` or candidate
// `done` without being re-rejected by draft source-window checks.
func TestStrictContractExit_PartialReadAcceptedContractSurvivesDone(t *testing.T) {
	for _, withCandidate := range []bool{false, true} {
		name := "empty_done"
		if withCandidate {
			name = "candidate_done"
		}
		t.Run(name, func(t *testing.T) {
			root, run, cfg := setupStrictExitRun(t, 4)
			var longFn strings.Builder
			longFn.WriteString("int verify(void) {\n")
			for i := 2; i <= 23; i++ {
				longFn.WriteString("  int step_")
				longFn.WriteString(string(rune('a' + (i % 20))))
				longFn.WriteString(" = 1; (void)step_")
				longFn.WriteString(string(rune('a' + (i % 20))))
				longFn.WriteString(";\n")
			}
			longFn.WriteString("  return 1;\n}\n")
			if err := os.WriteFile(filepath.Join(root, "a.c"), []byte(longFn.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			scope := runfs.BuildScope("", "abc", root)
			if err := runfs.WriteJSON(runfs.ManifestPath(run), artifacts.Manifest{
				SchemaVersion: "teecheck.manifest.v1",
				RunID:         "reliable",
				LocalPath:     root,
				Commit:        "abc",
				Scope:         scope,
				Focus:         "tee",
			}); err != nil {
				t.Fatal(err)
			}

			var readRef string
			client := &scriptedStrictClient{t: t}
			client.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
				switch call {
				case 1:
					// Read ONLY lines 1..5 of the 25-line function!
					return map[string]any{"actions": []any{
						map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
						map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 5}},
					}}, ""
				case 2:
					m := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
					if len(m) != 2 {
						t.Fatalf("missing read_file ref: %s", req.Messages[0].Content)
					}
					readRef = m[1]
					return map[string]any{"actions": []any{
						map[string]any{"name": "open_audit_lead", "args": map[string]any{
							"security_question": "Does long verify enforce input preconditions?",
							"target_symbol_ids": []string{"a.c::verify"},
							"reason":            []string{"Header lacks input check."},
							"reason_fact_refs":  []string{readRef},
						}},
					}}, ""
				case 3:
					return map[string]any{"actions": []any{
						map[string]any{"name": "formalize_contract", "args": map[string]any{
							"lead_id":  "lead-s0-001",
							"contract": closingTestContract(),
						}},
					}}, ""
				case 4:
					if !strings.Contains(req.Messages[0].Content, "[formalize_contract] OK") {
						t.Fatalf("formalize_contract did not succeed in round 3: %s", req.Messages[0].Content)
					}
					doneArgs := map[string]any{
						"summary":    "concluding after accepted contract on partial read",
						"candidates": []any{},
					}
					if withCandidate {
						doneArgs["candidates"] = []any{map[string]any{
							"id": "cand-verify", "kind": "guard", "priority": "high",
							"paths": []string{"a.c"}, "symbols": []string{"verify"},
							"why_selected": []string{"already formalized in round 3"},
						}}
					}
					return map[string]any{"actions": []any{
						map[string]any{"name": "done", "args": doneArgs},
					}}, ""
				default:
					t.Fatalf("unexpected model call %d (accepted contract should not trigger closing subcall)", call)
					return nil, ""
				}
			}

			cfg.Client = client
			res := Run(context.Background(), cfg)
			if res.Err != nil {
				t.Fatal(res.Err)
			}
			if client.calls != 4 {
				t.Fatalf("calls = %d, want 4", client.calls)
			}
			if res.Bundle.PlannerMeta.TerminationReason != "llm_done" {
				t.Fatalf("TerminationReason = %q, want llm_done", res.Bundle.PlannerMeta.TerminationReason)
			}
			if len(res.Bundle.Errors) != 0 {
				t.Fatalf("unexpected re-binding errors on accepted contract: %+v", res.Bundle.Errors)
			}
			if len(res.CasePacks) != 1 || len(res.CasePacks[0].CaseInvariants) != 1 {
				t.Fatalf("accepted contract was lost on done: packs=%+v", res.CasePacks)
			}
			got := res.CasePacks[0].CaseInvariants[0]
			if got.Grounding != "source_bound" || got.Subjects[0].StartLine != 1 || got.Subjects[0].EndLine != 25 {
				t.Fatalf("unexpected bound subject span: %+v", got)
			}
		})
	}
}

// Regression 5 (Codex Review #4): If contract binding succeeds in `done`
// (appending `formalized` to audit_leads.jsonl and updating in-memory state) and
// round persistence subsequently fails (`persist_error`), the on-disk Checkpoint
// MUST retain the previous committed snapshot + journal boundaries so `--resume`
// rolls back the uncommitted suffix cleanly and completes on retry.
func TestStrictContractExit_CommitFailureAfterBindingPreservesConsistentResumableCheckpoint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0400 write-failure simulation requires non-root user")
	}
	_, run, cfg := setupStrictExitRun(t, 5)
	roundsPath := runfs.RoundsLogPath(run)
	leadsPath := runfs.AuditLeadsPath(run)

	var readRef string
	failAttempt := &scriptedStrictClient{t: t}
	failAttempt.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
		switch call {
		case 1:
			return map[string]any{"actions": []any{
				map[string]any{"name": "list_dir", "args": map[string]any{"path": ".", "depth": 1}},
				map[string]any{"name": "read_file", "args": map[string]any{"path": "a.c", "start": 1, "end": 4}},
			}}, ""
		case 2:
			m := regexp.MustCompile(`\[read_file\] OK\s+ref=(\S+)`).FindStringSubmatch(req.Messages[0].Content)
			readRef = m[1]
			return map[string]any{"actions": []any{
				map[string]any{"name": "open_audit_lead", "args": map[string]any{
					"security_question": "Does verify check input?",
					"target_symbol_ids": []string{"a.c::verify"},
					"reason":            []string{"Observed unconditional return."},
					"reason_fact_refs":  []string{readRef},
				}},
			}}, ""
		case 3:
			// Make rounds.jsonl read-only right before returning round 3's reply:
			// saveProgress(nil) writes state.json, bindPlannerContractsWithState
			// appends `formalized` to audit_leads.jsonl, and AppendRoundAndPersist
			// then fails on rounds.jsonl!
			if err := os.Chmod(roundsPath, 0o400); err != nil {
				t.Fatal(err)
			}
			return map[string]any{"actions": []any{
				map[string]any{"name": "done", "args": map[string]any{
					"summary":         "valid contract before persist failure",
					"candidates":      []any{},
					"case_invariants": []artifacts.CaseInvariantV2{closingTestContract()},
				}},
			}}, ""
		default:
			t.Fatalf("unexpected call %d in failing attempt", call)
			return nil, ""
		}
	}

	cfg.Client = failAttempt
	res1 := Run(context.Background(), cfg)
	_ = os.Chmod(roundsPath, 0o600)
	if res1.Err == nil || res1.Bundle.PlannerMeta.TerminationReason != "persist_error" {
		t.Fatalf("expected persist_error, got err=%v reason=%s", res1.Err, res1.Bundle.PlannerMeta.TerminationReason)
	}

	// Confirm binding really wrote the uncommitted `formalized` line to audit_leads.jsonl.
	rawLeadsBeforeRestore, err := os.ReadFile(leadsPath)
	if err != nil || !strings.Contains(string(rawLeadsBeforeRestore), `"formalized"`) {
		t.Fatalf("expected uncommitted formalized lead in audit_leads.jsonl before recovery, got: %s (%v)", rawLeadsBeforeRestore, err)
	}

	// InspectCheckpoint MUST pass and hold Round 2's consistent state (open lead, 0 contracts).
	cp, err := InspectCheckpoint(run, cfg.RepoRoot)
	if err != nil {
		t.Fatalf("InspectCheckpoint failed after mid-round commit error: %v", err)
	}
	if cp.LastCommittedRound != 2 || len(cp.State.AuditLeads) != 1 || cp.State.AuditLeads[0].State != artifacts.LeadStateOpen || len(cp.State.Contracts) != 0 {
		t.Fatalf("checkpoint mixed uncommitted round-3 state with round-2 journal offsets: round=%d leads=%+v contracts=%+v",
			cp.LastCommittedRound, cp.State.AuditLeads, cp.State.Contracts)
	}

	// Now resume and verify clean journal rollback + completion!
	resumeClient := &scriptedStrictClient{t: t}
	resumeClient.stepFn = func(call int, req llm.GenerateRequest) (any, string) {
		if call != 1 {
			t.Fatalf("unexpected resume call %d", call)
		}
		return map[string]any{"actions": []any{
			map[string]any{"name": "done", "args": map[string]any{
				"summary":         "completed cleanly on resume",
				"candidates":      []any{},
				"case_invariants": []artifacts.CaseInvariantV2{closingTestContract()},
			}},
		}}, ""
	}
	cfg.Resume = true
	cfg.Client = resumeClient
	res2 := Run(context.Background(), cfg)
	if res2.Err != nil {
		t.Fatalf("resumed Run failed: %v", res2.Err)
	}
	if res2.Bundle.PlannerMeta.TerminationReason != "llm_done" || len(res2.CasePacks) != 1 {
		t.Fatalf("resumed run termination=%s packs=%+v", res2.Bundle.PlannerMeta.TerminationReason, res2.CasePacks)
	}
	cpAfter, err := InspectCheckpoint(run, cfg.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !cpAfter.Completed || cpAfter.State.AuditLeads[0].State != artifacts.LeadStateFormalized || len(cpAfter.State.Contracts) != 1 {
		t.Fatalf("final resumed checkpoint invalid: %+v", cpAfter)
	}
}
