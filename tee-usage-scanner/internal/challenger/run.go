package challenger

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/tools"
)

// Run drives the two-phase Challenger (§7.7, §25) for every case pack
// in the run:
//
//	Phase 1 (independent): builds a ChallengerIndependentView from
//	ONLY the CasePack + its loaded caseContext (TWE knowledge,
//	Architecture slice, Invariants, ToolFacts) — the Expert's
//	Hypothesis is not read until AFTER phase 1 is persisted. This
//	ordering is deliberate, not incidental: hypothesisPath is not even
//	computed until after independentView has been written to disk, so
//	a future edit that tried to "peek ahead" would have to add a new
//	read, not just reorder two already-present statements.
//
//	Phase 2 (comparative): reads the Hypothesis, computes
//	KeyDifferences against the phase-1 view, and produces the final
//	Challenge.
func Run(cfg config.Config, client llm.Client) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	toolAdapter := tools.NewLocalAdapter()

	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", casePath, err)
		}

		// ── Phase 1: independent judgment, no Hypothesis in scope. ──
		caseCtx := loadCaseContext(cfg.RunDir, pack)
		independentView, err := buildIndependentViewLLM(context.Background(), client, toolAdapter, manifest.LocalPath, pack, caseCtx, cfg.AgentID, cfg.LLMTemp)
		if err != nil {
			return fmt.Errorf("challenger phase-1 llm for %s: %w", pack.CaseID, err)
		}
		independentPath := filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("independent-%03d.json", idx+1))
		if err := runfs.WriteJSON(independentPath, independentView); err != nil {
			return fmt.Errorf("write independent view %s: %w", independentView.CaseID, err)
		}

		// ── Phase 2: now read the Expert hypothesis and diff. ──
		var hypothesis artifacts.Hypothesis
		hypothesisPath := filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1))
		if err := runfs.ReadJSON(hypothesisPath, &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis %s: %w", hypothesisPath, err)
		}

		challenge, err := buildChallengeLLM(context.Background(), client, toolAdapter, manifest.LocalPath, pack, hypothesis, independentView, cfg.AgentID, cfg.LLMTemp)
		if err != nil {
			return fmt.Errorf("challenger phase-2 llm for %s: %w", pack.CaseID, err)
		}
		challenge.IndependentViewPath = independentPath

		target := filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, challenge); err != nil {
			return fmt.Errorf("write challenge %s: %w", challenge.CaseID, err)
		}
		count++
	}
	fmt.Printf("Wrote %d challenge file(s) to %s\n", count, runfs.ChallengerDir(cfg.RunDir))
	return nil
}

func buildChallengeLLM(ctx context.Context, client llm.Client, toolAdapter tools.Adapter, repoRoot string, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, independent artifacts.ChallengerIndependentView, agentID string, temperature float64) (artifacts.Challenge, error) {
	searchTerms := append([]string{}, hypothesis.MissingObligations...)
	searchTerms = append(searchTerms, "caller", "bind", "verify", "authorize", "wrapper")
	toolHits, err := toolAdapter.SearchKeywords(ctx, repoRoot, pack.TargetFiles, searchTerms, 8)
	if err != nil {
		return artifacts.Challenge{}, err
	}

	// Phase 2 (§7.7): the Challenger already formed an independent
	// judgment in phase 1, before ever seeing this hypothesis. The
	// prompt below is framed as a COMPARISON against that prior
	// judgment, not as "challenge the expert's conclusion" from the
	// first token — the self-confirmation failure mode §25 exists to
	// fix.
	system := `You are the Challenger Agent in TEECheck, now in phase 2 of a two-phase review (§7.7, §25). You already formed an independent judgment in phase 1 WITHOUT seeing the Expert's hypothesis (reproduced below as "Your phase-1 independent view"). Now compare that independent view against the Expert's hypothesis and report where they genuinely differ — do not simply restate agreement with the Expert. Reason like an attacker and skeptic. Return exactly one JSON object.`
	user := fmt.Sprintf(`Return a JSON object with fields:
- exploit_narrative
- counter_arguments (array of strings)
- remaining_questions (array of strings)
- suggested_checks (array of strings)
- exploitability (string)
- reviewer_stance (string)
- key_differences (array of strings — where your phase-1 independent view and the Expert hypothesis actually disagree)

Case:
- case_id: %s
- category: %s
- target_files: %s
- target_symbols: %s
- open_questions: %s

Your phase-1 independent view (formed WITHOUT the Expert hypothesis):
- issue_present: %v
- reasoning: %s
- defenses_considered: %s
- counter_examples: %s
- confidence: %s

Expert hypothesis:
- title: %s
- summary: %s
- suspected_issue: %s
- missing_obligations: %s
- supporting_facts: %s
- confidence: %s

Knowledge hints:
%s

Tool hits:
%s

Snippets:
%s
`, pack.CaseID, pack.Category, strings.Join(pack.TargetFiles, ", "), strings.Join(pack.TargetSymbols, ", "), strings.Join(pack.OpenQuestions, " | "),
		independent.IssuePresent, independent.Reasoning, strings.Join(independent.DefensesConsidered, " | "), strings.Join(independent.CounterExamples, " | "), independent.Confidence,
		hypothesis.Title, hypothesis.Summary, hypothesis.SuspectedIssue, strings.Join(hypothesis.MissingObligations, ", "), strings.Join(hypothesis.SupportingFacts, " | "), hypothesis.Confidence,
		formatKnowledgeHints(pack.KnowledgeHints), formatToolHits(toolHits), formatSnippets(pack.Snippets))

	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: system,
		Messages: []llm.Message{
			{Role: "user", Content: user},
		},
		Temperature: temperature,
		JSONMode:    true,
	})
	if err != nil {
		return artifacts.Challenge{}, err
	}

	var parsed struct {
		ExploitNarrative   string   `json:"exploit_narrative"`
		CounterArguments   []string `json:"counter_arguments"`
		RemainingQuestions []string `json:"remaining_questions"`
		SuggestedChecks    []string `json:"suggested_checks"`
		Exploitability     string   `json:"exploitability"`
		ReviewerStance     string   `json:"reviewer_stance"`
		KeyDifferences     []string `json:"key_differences"`
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return artifacts.Challenge{}, fmt.Errorf("parse challenger json: %w | raw=%s", err, truncate(resp.Text, 400))
	}

	keyDiffs := uniq(parsed.KeyDifferences)
	if len(keyDiffs) == 0 {
		// The LLM may ignore the new field; fall back to the
		// deterministic comparison so KeyDifferences is never
		// silently empty just because the model skipped it.
		keyDiffs = computeKeyDifferences(hypothesis, independent)
	}

	return artifacts.Challenge{
		SchemaVersion:           "teecheck.challenge.v1",
		CaseID:                  pack.CaseID,
		AgentID:                 agentID,
		ExploitNarrative:        firstNonEmpty(parsed.ExploitNarrative, fmt.Sprintf("If the suspected %s gap is real, an attacker may abuse %s.", pack.Category, primaryLabel(pack))),
		CounterArguments:        uniq(parsed.CounterArguments),
		RemainingQuestions:      uniq(append(parsed.RemainingQuestions, pack.OpenQuestions...)),
		SuggestedChecks:         uniq(append(parsed.SuggestedChecks, flattenToolHits(toolHits)...)),
		Exploitability:          normalizeExploitability(parsed.Exploitability, hypothesis.Confidence),
		ReviewerStance:          firstNonEmpty(parsed.ReviewerStance, "challenge_required"),
		IndependentIssuePresent: independent.IssuePresent,
		KeyDifferences:          keyDiffs,
	}, nil
}

func primaryLabel(pack artifacts.CasePack) string {
	if len(pack.TargetSymbols) > 0 {
		return pack.TargetSymbols[0]
	}
	if len(pack.TargetFiles) > 0 {
		return pack.TargetFiles[0]
	}
	return pack.CaseID
}

func formatKnowledgeHints(hints []artifacts.KnowledgeHint) string {
	if len(hints) == 0 {
		return "- none"
	}
	lines := make([]string, 0, len(hints))
	for _, hint := range hints {
		lines = append(lines, fmt.Sprintf("- %s (%s): %s", hint.Title, strings.Join(hint.Tags, ","), hint.Reason))
	}
	return strings.Join(lines, "\n")
}

func formatToolHits(hits []tools.SearchHit) string {
	if len(hits) == 0 {
		return "- none"
	}
	lines := make([]string, 0, len(hits))
	for _, hit := range hits {
		lines = append(lines, fmt.Sprintf("- %s:%d %s", hit.Path, hit.Line, hit.Text))
	}
	return strings.Join(lines, "\n")
}

func flattenToolHits(hits []tools.SearchHit) []string {
	var out []string
	for _, hit := range hits {
		out = append(out, fmt.Sprintf("%s:%d %s", hit.Path, hit.Line, hit.Text))
	}
	return out
}

func formatSnippets(snippets []artifacts.PromptSnippet) string {
	if len(snippets) == 0 {
		return "- none"
	}
	lines := make([]string, 0, len(snippets))
	for _, snippet := range snippets {
		lines = append(lines, fmt.Sprintf("FILE %s (%d-%d)\n%s", snippet.Path, snippet.StartLine, snippet.EndLine, snippet.Content))
	}
	return strings.Join(lines, "\n\n")
}

func normalizeExploitability(value, expertConfidence string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "proven", "likely", "theoretical", "unlikely":
		return value
	}
	if expertConfidence == "high" {
		return "likely"
	}
	return "theoretical"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func uniq(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "..."
}
