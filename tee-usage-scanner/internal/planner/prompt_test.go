package planner_test

import (
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/trustirfacts"
	"strings"
	"testing"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/planner"
)

func TestBuildSystemPrompt_MentionsActions(t *testing.T) {
	available := []string{"list_dir", "read_file", "ripgrep", "tree_sitter_outline", "reverse_trace", "done"}
	prompt := planner.BuildSystemPrompt(available, "", planner.PriorKnowledge{})

	for _, name := range available {
		if !strings.Contains(prompt, name) {
			t.Errorf("system prompt missing action %q", name)
		}
	}
}

func TestBuildSystemPrompt_InjectsObligations(t *testing.T) {
	block := "### attestation-identity-verification\nQuote and report verification."
	prompt := planner.BuildSystemPrompt([]string{"done"}, block, planner.PriorKnowledge{})
	if !strings.Contains(prompt, "SECURITY OBLIGATIONS") {
		t.Error("obligations header missing when block is non-empty")
	}
	if !strings.Contains(prompt, "attestation-identity-verification") {
		t.Error("obligations content missing from prompt")
	}
}

func TestBuildSystemPrompt_SkipsObligationsWhenEmpty(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done"}, "", planner.PriorKnowledge{})
	if strings.Contains(prompt, "SECURITY OBLIGATIONS") {
		t.Error("obligations header should not appear when block is empty")
	}
}

func TestBuildSystemPrompt_ExplainsResponseFormat(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done"}, "", planner.PriorKnowledge{})
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

func TestBuildRoundPrompt_IncludesStickyPlaybookDetail(t *testing.T) {
	state := planner.NewState("run-001")
	state.AddPlaybookDetail("TWE-STATE-001", "Attacker: replays persisted state wholesale.")

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if !strings.Contains(prompt, "TWE PLAYBOOK DETAIL") {
		t.Error("round prompt missing sticky playbook detail header")
	}
	if !strings.Contains(prompt, "TWE-STATE-001") {
		t.Error("round prompt missing pulled TWE id")
	}
	if !strings.Contains(prompt, "Attacker: replays persisted state wholesale.") {
		t.Error("round prompt missing pulled detail text")
	}
}

func TestBuildRoundPrompt_StickyPlaybookDetailIsNotTruncated(t *testing.T) {
	state := planner.NewState("run-001")

	// Longer than the 1500-char RECENT ROUNDS truncation that action
	// Output goes through — the sticky block must carry it in full
	// regardless, for as many rounds as the loop runs, not just the last 2.
	head := "Investigate: " + strings.Repeat("x", 2000)
	tail := "END-OF-DETAIL-MARKER"
	detail := head + tail
	if len(detail) <= 1500 {
		t.Fatalf("test detail is only %d chars; must exceed 1500 to prove no truncation", len(detail))
	}
	state.AddPlaybookDetail("TWE-STATE-001", detail)

	// Push the detail's originating round out of the RECENT ROUNDS window
	// (last 2 rounds) to prove the sticky block, not RECENT ROUNDS, is what
	// carries it.
	for i := 1; i <= 4; i++ {
		state.AppendRound(artifacts.RoundRecord{Round: i, Thought: "unrelated round"})
	}

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if !strings.Contains(prompt, tail) {
		t.Errorf("round prompt truncated the sticky playbook detail before its tail marker %q", tail)
	}
}

func TestPlannerState_AddPlaybookDetailDedupesByID(t *testing.T) {
	state := planner.NewState("run-001")
	state.AddPlaybookDetail("TWE-STATE-001", "first pull")
	state.AddPlaybookDetail("TWE-STATE-001", "second pull should be ignored")

	if len(state.PlaybookDetails) != 1 {
		t.Fatalf("expected 1 stored detail, got %d", len(state.PlaybookDetails))
	}
	if state.PlaybookDetails[0].Text != "first pull" {
		t.Errorf("expected first pull to win, got %q", state.PlaybookDetails[0].Text)
	}
}

// ─── §7.5/§24: TWE/Architecture/Invariant prior-knowledge injection ──────

func TestBuildSystemPrompt_InjectsTWEContext(t *testing.T) {
	knowledge := planner.PriorKnowledge{TWEText: "[TWE-STATE-001] Trusted State Rollback | family=State\n"}
	prompt := planner.BuildSystemPrompt([]string{"done"}, "", knowledge)
	if !strings.Contains(prompt, "TWE-STATE-001") {
		t.Error("system prompt missing injected TWE context")
	}
	if !strings.Contains(prompt, "TWE PRIOR KNOWLEDGE") {
		t.Error("system prompt missing TWE prior-knowledge header")
	}
}

func TestBuildSystemPrompt_InjectsArchitectureSlice(t *testing.T) {
	model := &artifacts.ArchitectureModel{
		Components: []artifacts.ArchitectureElement{
			{ID: "comp:loader", Kind: "component", Name: "TA loader", State: artifacts.EvidenceObserved},
		},
	}
	prompt := planner.BuildSystemPrompt([]string{"done"}, "", planner.PriorKnowledge{Architecture: model})
	if !strings.Contains(prompt, "comp:loader") {
		t.Error("system prompt missing architecture element id")
	}
	if !strings.Contains(prompt, "ARCHITECTURE MODEL") {
		t.Error("system prompt missing architecture header")
	}
}

func TestBuildSystemPrompt_InjectsProjectInvariants(t *testing.T) {
	invs := []artifacts.ProjectInvariant{{
		InvariantID: "INV-STATE-001",
		Statement:   "subkey_version must propagate to check_update_version",
		RelatedTWEs: []string{"TWE-STATE-001"},
	}}
	prompt := planner.BuildSystemPrompt([]string{"done"}, "", planner.PriorKnowledge{Invariants: invs})
	if !strings.Contains(prompt, "INV-STATE-001") {
		t.Error("system prompt missing invariant id")
	}
	if !strings.Contains(prompt, "check_update_version") {
		t.Error("system prompt missing invariant statement")
	}
	if !strings.Contains(prompt, "PROJECT INVARIANTS") {
		t.Error("system prompt missing invariants header")
	}
}

func TestBuildSystemPrompt_SkipsPriorKnowledgeSectionsWhenEmpty(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done"}, "", planner.PriorKnowledge{})
	for _, header := range []string{"TWE PRIOR KNOWLEDGE", "ARCHITECTURE MODEL", "PROJECT INVARIANTS"} {
		if strings.Contains(prompt, header) {
			t.Errorf("prompt should not contain %q when PriorKnowledge is empty", header)
		}
	}
}

// TestBuildSystemPrompt_MissingRoleIsATaskNotAConclusion is the §24
// acceptance criterion "Planner 不因 missing role 直接输出 confirmed
// finding" and "Planner 不因 query 未命中直接输出「安全」" made a prompt-level
// assertion: the rule must be stated explicitly, every run, regardless of
// PriorKnowledge content.
func TestBuildSystemPrompt_MissingRoleIsATaskNotAConclusion(t *testing.T) {
	prompt := planner.BuildSystemPrompt([]string{"done", "fact_layer_query"}, "", planner.PriorKnowledge{})
	if !strings.Contains(prompt, "NEXT INVESTIGATIVE TASK") {
		t.Error("system prompt must state that a missing role is the next task, not a conclusion")
	}
	if !strings.Contains(prompt, "NOT a vulnerability conclusion") && !strings.Contains(prompt, "NOT evidence of safety") {
		t.Error("system prompt must state a missing role is neither a vulnerability conclusion nor evidence of safety")
	}
	if !strings.Contains(prompt, "unresolved") || !strings.Contains(prompt, "Never conclude safety") {
		t.Error("system prompt must state that an unresolved/unmatched fact-layer query is not evidence of safety (§6.5)")
	}
	if !strings.Contains(prompt, "fact_layer_query") {
		t.Error("system prompt should document the fact_layer_query action's args schema")
	}
}

// ─── §7.5/§24: active investigations tracked across rounds ───────────────

func TestBuildRoundPrompt_IncludesActiveInvestigations(t *testing.T) {
	state := planner.NewState("run-001")
	state.AddInvestigations([]artifacts.TWEInvestigation{{
		InvestigationID: "inv-state-001-abc123",
		TWEIDs:          []string{"TWE-STATE-001"},
		Classification:  "standard",
		FilledRoles: map[string]artifacts.ToolLocation{
			"claim_producer": {Path: "core/crypto/signed_hdr.c", StartLine: 262},
		},
		MissingRoles:     []string{"rollback_authority"},
		RequiredEvidence: []string{"reachable_restore_or_load_path"},
		CoverageGaps:     []string{"attack chain incomplete: missing role(s) rollback_authority"},
	}})

	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if !strings.Contains(prompt, "inv-state-001-abc123") {
		t.Error("round prompt missing investigation id")
	}
	if !strings.Contains(prompt, "claim_producer=core/crypto/signed_hdr.c:262") {
		t.Error("round prompt missing filled role location")
	}
	if !strings.Contains(prompt, "MISSING ROLES") || !strings.Contains(prompt, "rollback_authority") {
		t.Error("round prompt missing the missing-role reminder")
	}
	if !strings.Contains(prompt, "NOT a vulnerability conclusion") {
		t.Error("round prompt's missing-role line must restate that it is not a conclusion")
	}
}

func TestBuildRoundPrompt_OmitsInvestigationsHeaderWhenEmpty(t *testing.T) {
	state := planner.NewState("run-001")
	prompt := planner.BuildRoundPrompt(state, planner.PromptProfile{}, planner.NewDefaultBudget(), nil)
	if strings.Contains(prompt, "ACTIVE TWE INVESTIGATIONS") {
		t.Error("investigations header should not appear when there are none")
	}
}

func TestBuildSystemPrompt_DocumentsPlaybookDetailAction(t *testing.T) {
	out := planner.BuildSystemPrompt([]string{"ripgrep", "twe_playbook_detail", "done"}, "", planner.PriorKnowledge{})
	// Verify the action name appears
	if !strings.Contains(out, "twe_playbook_detail") {
		t.Error("system prompt must document the twe_playbook_detail action")
	}
	// Verify the exact rendered format: "- twe_playbook_detail  args={...with twe_id inside...}"
	// This ensures actionArgSchemas["twe_playbook_detail"] exists and documents twe_id,
	// not just that twe_id appears elsewhere (done action has "twe_ids" by coincidence).
	if !strings.Contains(out, "- twe_playbook_detail  args={\"twe_id\"") {
		t.Error("system prompt must document twe_playbook_detail's args with twe_id schema (not fallback {...})")
	}
}

// TestBuildSystemPrompt_Deanchored is the de-anchoring acceptance test: the
// system prompt must not steer the planner toward a deleted action
// (sink_catalog_lookup) or a single language (*.rs, Cargo). It must instead
// point the planner at TWE/invariant-driven investigation.
func TestBuildSystemPrompt_Deanchored(t *testing.T) {
	out := planner.BuildSystemPrompt([]string{"ripgrep", "tree_sitter_outline", "done"}, "", planner.PriorKnowledge{})
	for _, banned := range []string{"sink_catalog_lookup", `globs=["*.rs"]`, "Cargo", "*.rs"} {
		if strings.Contains(out, banned) {
			t.Errorf("system prompt still contains anchoring text %q", banned)
		}
	}
	for _, want := range []string{"invariant", "TWE"} {
		if !strings.Contains(out, want) {
			t.Errorf("system prompt missing guidance token %q", want)
		}
	}
}

// Every other planner action takes arguments a model can derive from the
// code in front of it. fact_layer_query alone requires a value from a
// closed vocabulary only the source knew, and the schema carried one "e.g."
// and no list. The model failed in both available directions: it invented
// an operation that does not exist (2026-07-27), and across three runs on
// 2026-07-29 — one of them against a repository that DID have a fact table,
// with CodeQL installed and the action registered — it never called the
// action at all, never mentioning the fact layer in eight rounds.
func TestBuildSystemPrompt_EnumeratesFactLayerOperations(t *testing.T) {
	prompt := planner.BuildSystemPrompt(
		[]string{"fact_layer_query", "read_file"}, "", planner.PriorKnowledge{})

	ops := trustirfacts.SupportedOperationStrings()
	if len(ops) == 0 {
		t.Skip("no executable operations in this build")
	}
	for _, op := range ops {
		if !strings.Contains(prompt, op) {
			t.Errorf("operation %q is executable but absent from the prompt — the model cannot ask for what it cannot see", op)
		}
	}
	if !strings.Contains(prompt, "one of:") {
		t.Error("the schema must present the operations as a closed list, not as an example")
	}
	// The old shape said "e.g." — a single sample the model had to guess from.
	if strings.Contains(prompt, `(e.g. "cpp.state.rollback_version_propagation")`) {
		t.Error("the example-only schema is back; a lone e.g. is what made the vocabulary unknowable")
	}
}
