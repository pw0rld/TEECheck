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

func Run(cfg config.Config) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	var client llm.Client
	if strings.EqualFold(cfg.ChallengeMode, "llm") {
		client = llm.NewClient(cfg)
	}
	toolAdapter := tools.NewLocalAdapter()

	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", casePath, err)
		}
		var hypothesis artifacts.Hypothesis
		hypothesisPath := filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1))
		if err := runfs.ReadJSON(hypothesisPath, &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis %s: %w", hypothesisPath, err)
		}

		var challenge artifacts.Challenge
		if strings.EqualFold(cfg.ChallengeMode, "llm") {
			challenge, err = buildChallengeLLM(context.Background(), client, toolAdapter, manifest.LocalPath, pack, hypothesis, cfg.AgentID, cfg.LLMTemp)
			if err != nil {
				return fmt.Errorf("challenger llm for %s: %w", pack.CaseID, err)
			}
		} else {
			challenge = buildChallengeHeuristic(pack, hypothesis, cfg.AgentID)
		}

		target := filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, challenge); err != nil {
			return fmt.Errorf("write challenge %s: %w", challenge.CaseID, err)
		}
		count++
	}
	fmt.Printf("Wrote %d challenge file(s) to %s\n", count, runfs.ChallengerDir(cfg.RunDir))
	return nil
}

func buildChallengeLLM(ctx context.Context, client llm.Client, toolAdapter tools.Adapter, repoRoot string, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, agentID string, temperature float64) (artifacts.Challenge, error) {
	searchTerms := append([]string{}, hypothesis.MissingObligations...)
	searchTerms = append(searchTerms, "caller", "bind", "verify", "authorize", "wrapper")
	toolHits, err := toolAdapter.SearchKeywords(ctx, repoRoot, pack.TargetFiles, searchTerms, 8)
	if err != nil {
		return artifacts.Challenge{}, err
	}

	system := "You are the Challenger Agent in TEECheck. Challenge the expert's conclusion and reason like an attacker and skeptic. Return exactly one JSON object."
	user := fmt.Sprintf(`Return a JSON object with fields:
- exploit_narrative
- counter_arguments (array of strings)
- remaining_questions (array of strings)
- suggested_checks (array of strings)
- exploitability (string)
- reviewer_stance (string)

Case:
- case_id: %s
- category: %s
- target_files: %s
- target_symbols: %s
- open_questions: %s

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
`, pack.CaseID, pack.Category, strings.Join(pack.TargetFiles, ", "), strings.Join(pack.TargetSymbols, ", "), strings.Join(pack.OpenQuestions, " | "), hypothesis.Title, hypothesis.Summary, hypothesis.SuspectedIssue, strings.Join(hypothesis.MissingObligations, ", "), strings.Join(hypothesis.SupportingFacts, " | "), hypothesis.Confidence, formatKnowledgeHints(pack.KnowledgeHints), formatToolHits(toolHits), formatSnippets(pack.Snippets))

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
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return artifacts.Challenge{}, fmt.Errorf("parse challenger json: %w | raw=%s", err, truncate(resp.Text, 400))
	}

	return artifacts.Challenge{
		SchemaVersion:      "teecheck.challenge.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		ExploitNarrative:   firstNonEmpty(parsed.ExploitNarrative, fmt.Sprintf("If the suspected %s gap is real, an attacker may abuse %s.", pack.Category, primaryLabel(pack))),
		CounterArguments:   uniq(parsed.CounterArguments),
		RemainingQuestions: uniq(append(parsed.RemainingQuestions, pack.OpenQuestions...)),
		SuggestedChecks:    uniq(append(parsed.SuggestedChecks, flattenToolHits(toolHits)...)),
		Exploitability:     normalizeExploitability(parsed.Exploitability, hypothesis.Confidence),
		ReviewerStance:     firstNonEmpty(parsed.ReviewerStance, "challenge_required"),
	}, nil
}

func buildChallengeHeuristic(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, agentID string) artifacts.Challenge {
	counterArgs := []string{
		"The current case may omit helper or wrapper context that completes validation.",
	}
	if len(pack.KnowledgeHints) == 0 {
		counterArgs = append(counterArgs, "No matching knowledge pages were found, which lowers confidence in pattern matching.")
	}
	remaining := append([]string{}, pack.OpenQuestions...)
	if len(remaining) == 0 {
		remaining = append(remaining, "Is the visible snippet the true trust decision site?")
	}
	checks := []string{
		"Search surrounding wrappers for caller binding or validation helpers.",
		"Confirm whether failure paths actually stop execution.",
	}
	exploitability := "theoretical"
	reviewerStance := "challenge_required"
	if hypothesis.Confidence == "high" {
		exploitability = "likely"
		reviewerStance = "pressure_test"
	}
	return artifacts.Challenge{
		SchemaVersion:      "teecheck.challenge.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		ExploitNarrative:   fmt.Sprintf("If the suspected %s gap is real, an attacker may cross the boundary through %s without the expected safeguards.", pack.Category, primaryLabel(pack)),
		CounterArguments:   counterArgs,
		RemainingQuestions: remaining,
		SuggestedChecks:    checks,
		Exploitability:     exploitability,
		ReviewerStance:     reviewerStance,
	}
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
