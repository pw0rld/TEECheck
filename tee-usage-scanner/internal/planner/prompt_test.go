package planner_test

import (
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestBuildSystemPrompt_MentionsActions(t *testing.T) {
	available := []string{"list_dir", "read_file", "ripgrep", "tree_sitter_outline", "sink_catalog_lookup", "reverse_trace", "done"}
	prompt := planner.BuildSystemPrompt(available, "")

	for _, name := range available {
		if !strings.Contains(prompt, name) {
			t.Errorf("system prompt missing action %q", name)
		}
	}
}

func TestBuildSystemPrompt_InjectsObligations(t *testing.T) {
	block := "### attestation-identity-verification\nQuote and report verification."
	prompt := planner.BuildSystemPrompt([]string{"done"}, block)
	if !strings.Contains(prompt, "SECURITY OBLIGATIONS") {
		t.Error("obligations header missing when block is non-empty")
	}
	if !strings.Contains(prompt, "attestation-identity-verification") {
		t.Error("obligations content missing from prompt")
	}
}

func TestBuildSystemPrompt_SkipsObligationsWhenEmpty(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done"}, "")
	if strings.Contains(prompt, "SECURITY OBLIGATIONS") {
		t.Error("obligations header should not appear when block is empty")
	}
}

func TestBuildSystemPrompt_ExplainsResponseFormat(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done"}, "")
	if !strings.Contains(prompt, "thought") {
		t.Error("system prompt missing 'thought' field instruction")
	}
	if !strings.Contains(prompt, "actions") {
		t.Error("system prompt missing 'actions' field instruction")
	}
	if !strings.Contains(prompt, "JSON") && !strings.Contains(prompt, "json") {
		t.Error("system prompt does not mention JSON")
	}
}

func TestBuildRoundPrompt_IncludesProfile(t *testing.T) {
	state := planner.NewState("run-001")
	budget := planner.NewDefaultBudget()
	budget.Start()
	profile := planner.PromptProfile{
		RepoURL:        "https://github.com/example/foo",
		Languages:      []string{"rust"},
		FrameworkHints: []string{"sgx"},
		FileCount:      1234,
	}

	prompt := planner.BuildRoundPrompt(state, profile, budget, nil)
	if !strings.Contains(prompt, "rust") {
		t.Error("round prompt missing language")
	}
	if !strings.Contains(prompt, "sgx") {
		t.Error("round prompt missing framework hint")
	}
	if !strings.Contains(prompt, "1234") {
		t.Error("round prompt missing file count")
	}
}

func TestBuildRoundPrompt_IncludesBudget(t *testing.T) {
	state := planner.NewState("run-001")
	budget := planner.Budget{MaxRounds: 8, MaxTokens: 120000}
	budget.Start()
	budget.ConsumeRound()
	budget.ConsumeRound()
	budget.ConsumeTokens(15000)

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, budget, nil)
	if !strings.Contains(prompt, "2/8") && !strings.Contains(prompt, "2 / 8") {
		t.Errorf("round prompt missing rounds budget: %s", prompt)
	}
	if !strings.Contains(prompt, "15000") {
		t.Errorf("round prompt missing tokens used: %s", prompt)
	}
}

func TestBuildRoundPrompt_IncludesRecentObservations(t *testing.T) {
	state := planner.NewState("run-001")
	state.AppendRound(artifacts.RoundRecord{
		Round:   1,
		Thought: "first look",
		Observations: []artifacts.RoundObservation{
			{Name: "list_dir", OK: true, Output: "attest/\nsgx/\n"},
		},
	})
	state.AppendRound(artifacts.RoundRecord{
		Round:   2,
		Thought: "drilling in",
		Observations: []artifacts.RoundObservation{
			{Name: "read_file", OK: true, Output: "1: fn verify_quote() {}"},
		},
	})

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if !strings.Contains(prompt, "verify_quote") {
		t.Error("round prompt missing recent observation content")
	}
	if !strings.Contains(prompt, "read_file") {
		t.Error("round prompt missing recent action name")
	}
}

func TestBuildRoundPrompt_IncludesAvoidPathsHeader(t *testing.T) {
	state := planner.NewState("run-001")
	avoid := []string{"attest/verifier/src/dcap.rs::DcapVerifier::verify", "sgx/service/src/lib.rs::verify_report"}

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), avoid)
	if !strings.Contains(prompt, "ALREADY COVERED BY PREVIOUS PASSES") {
		t.Error("avoid-paths header missing when list is non-empty")
	}
	if !strings.Contains(prompt, "DcapVerifier::verify") {
		t.Error("avoid-paths content missing from prompt")
	}
	if !strings.Contains(prompt, "sgx/service/src/lib.rs") {
		t.Error("second avoid entry missing")
	}
}

func TestBuildRoundPrompt_OmitsAvoidHeaderWhenEmpty(t *testing.T) {
	state := planner.NewState("run-001")
	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if strings.Contains(prompt, "ALREADY COVERED") {
		t.Error("avoid header should not appear when list is nil")
	}
}

func TestBuildRoundPrompt_IncludesCandidatesSoFar(t *testing.T) {
	state := planner.NewState("run-001")
	state.AddCandidates([]artifacts.Candidate{
		{ID: "candidate-001", Kind: "attestation", Paths: []string{"attest/verify.rs"}},
	})

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if !strings.Contains(prompt, "candidate-001") {
		t.Error("round prompt missing candidate id")
	}
	if !strings.Contains(prompt, "attest/verify.rs") {
		t.Error("round prompt missing candidate path")
	}
}
