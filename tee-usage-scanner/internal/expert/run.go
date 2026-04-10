package expert

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
	if strings.EqualFold(cfg.ExpertMode, "llm") {
		client = llm.NewClient(cfg)
	}
	toolAdapter := tools.NewLocalAdapter()

	count := 0
	for idx, path := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(path, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", path, err)
		}

		var hypothesis artifacts.Hypothesis
		if strings.EqualFold(cfg.ExpertMode, "llm") {
			hypothesis, err = buildHypothesisLLM(context.Background(), client, toolAdapter, manifest.LocalPath, pack, cfg.AgentID, cfg.LLMTemp)
			if err != nil {
				return fmt.Errorf("expert llm for %s: %w", pack.CaseID, err)
			}
		} else {
			hypothesis = buildHypothesisHeuristic(pack, cfg.AgentID)
		}

		target := filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, hypothesis); err != nil {
			return fmt.Errorf("write hypothesis %s: %w", hypothesis.CaseID, err)
		}
		count++
	}
	fmt.Printf("Wrote %d hypothesis file(s) to %s\n", count, runfs.ExpertDir(cfg.RunDir))
	return nil
}

func buildHypothesisLLM(ctx context.Context, client llm.Client, toolAdapter tools.Adapter, repoRoot string, pack artifacts.CasePack, agentID string, temperature float64) (artifacts.Hypothesis, error) {
	toolHits, err := toolAdapter.SearchKeywords(ctx, repoRoot, pack.TargetFiles, append(pack.ExpectedObligations, pack.TargetSymbols...), 8)
	if err != nil {
		return artifacts.Hypothesis{}, err
	}

	system := "You are the Expert Agent in TEECheck. Analyze the bounded case pack and return exactly one JSON object."
	user := fmt.Sprintf(`Return a JSON object with fields:
- title
- summary
- suspected_issue
- missing_obligations (array of strings)
- supporting_facts (array of strings)
- confidence ("low"|"medium"|"high")
- needs_verification (boolean)

Case:
- case_id: %s
- category: %s
- priority: %s
- target_files: %s
- target_symbols: %s
- expected_obligations: %s
- why_selected: %s
- graph_facts: %s
- open_questions: %s

Knowledge hints:
%s

Tool hits:
%s

Snippets:
%s
`, pack.CaseID, pack.Category, pack.Priority, strings.Join(pack.TargetFiles, ", "), strings.Join(pack.TargetSymbols, ", "), strings.Join(pack.ExpectedObligations, ", "), strings.Join(pack.WhySelected, " | "), strings.Join(pack.GraphFacts, " | "), strings.Join(pack.OpenQuestions, " | "), formatKnowledgeHints(pack.KnowledgeHints), formatToolHits(toolHits), formatSnippets(pack.Snippets))

	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: system,
		Messages: []llm.Message{
			{Role: "user", Content: user},
		},
		Temperature: temperature,
		JSONMode:    true,
	})
	if err != nil {
		return artifacts.Hypothesis{}, err
	}

	var parsed struct {
		Title              string   `json:"title"`
		Summary            string   `json:"summary"`
		SuspectedIssue     string   `json:"suspected_issue"`
		MissingObligations []string `json:"missing_obligations"`
		SupportingFacts    []string `json:"supporting_facts"`
		Confidence         string   `json:"confidence"`
		NeedsVerification  bool     `json:"needs_verification"`
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return artifacts.Hypothesis{}, fmt.Errorf("parse expert json: %w | raw=%s", err, truncate(resp.Text, 400))
	}

	return artifacts.Hypothesis{
		SchemaVersion:      "teecheck.hypothesis.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		Title:              firstNonEmpty(parsed.Title, fmt.Sprintf("Potential %s weakness in %s", pack.Category, primaryLabel(pack))),
		Summary:            firstNonEmpty(parsed.Summary, "The expert agent found a bounded concern that needs follow-up review."),
		SuspectedIssue:     firstNonEmpty(parsed.SuspectedIssue, pack.Category+" obligations may be incompletely enforced."),
		MissingObligations: uniq(parsed.MissingObligations),
		SupportingFacts:    uniq(append(parsed.SupportingFacts, flattenToolHits(toolHits)...)),
		KnowledgeHints:     pack.KnowledgeHints,
		Confidence:         normalizeConfidence(parsed.Confidence),
		NeedsVerification:  parsed.NeedsVerification,
	}, nil
}

func buildHypothesisHeuristic(pack artifacts.CasePack, agentID string) artifacts.Hypothesis {
	title := fmt.Sprintf("Potential %s weakness in %s", pack.Category, primaryLabel(pack))
	summary := fmt.Sprintf("The case suggests that %s may be incomplete around %s.", strings.Join(pack.ExpectedObligations, ", "), primaryLabel(pack))
	suspectedIssue := fmt.Sprintf("%s obligations may be incompletely enforced before the sensitive path proceeds.", pack.Category)
	confidence := "medium"
	needsVerification := true
	var facts []string
	var missing []string
	for _, snippet := range pack.Snippets {
		lower := strings.ToLower(snippet.Content)
		if strings.Contains(lower, "todo") || strings.Contains(lower, "missing") || strings.Contains(lower, "fixme") {
			facts = append(facts, fmt.Sprintf("snippet %s contains an explicit unfinished marker", snippet.Path))
			confidence = "high"
		}
		if strings.Contains(lower, "unsafe fallback") || strings.Contains(lower, "degrade") {
			facts = append(facts, fmt.Sprintf("snippet %s hints at degraded or fallback behavior", snippet.Path))
		}
	}
	if len(pack.ExpectedObligations) > 0 {
		missing = append(missing, pack.ExpectedObligations[0])
	}
	if len(facts) == 0 {
		facts = append(facts, pack.GraphFacts...)
	}
	return artifacts.Hypothesis{
		SchemaVersion:      "teecheck.hypothesis.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		Title:              title,
		Summary:            summary,
		SuspectedIssue:     suspectedIssue,
		MissingObligations: uniq(missing),
		SupportingFacts:    uniq(facts),
		KnowledgeHints:     pack.KnowledgeHints,
		Confidence:         confidence,
		NeedsVerification:  needsVerification,
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

func normalizeConfidence(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
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
