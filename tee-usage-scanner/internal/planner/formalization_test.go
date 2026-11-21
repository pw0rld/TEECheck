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
