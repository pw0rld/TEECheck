package expert

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/tools"
)

// Run is the standalone entry point used by the `expert` subcommand
// when invoked manually against an existing run dir. It delegates to
// RunWithEvents with no event sink, so manual reruns do not pollute
// (or revive) an events.jsonl that the original pipeline owned.
func Run(cfg config.Config) error {
	return RunWithEvents(cfg, nil, nil)
}

// RunWithEvents is the pipeline-facing entry point. The recorder and
// blob store are the same instances the planner/executor use, so
// claim_emitted events line up on the same seq stream as upstream
// stages. Either argument may be nil — emission is skipped silently
// in that case (Nop pattern, matching planner.RunConfig).
func RunWithEvents(cfg config.Config, rec events.Recorder, blobs *events.BlobStore) error {
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

		// Emit one claim_emitted event per CitedFact so consumers
		// can correlate claims with downstream verifier judgments
		// without having to re-read hypothesis-*.json. Events fire
		// even when Cited is empty (the agent asserted something
		// it could not anchor); downstream filtering decides what
		// to do with citation-less claims.
		if rec != nil {
			emitClaimEvents(rec, manifest.RunID, cfg.AgentID, hypothesis)
		}

		count++
	}
	fmt.Printf("Wrote %d hypothesis file(s) to %s\n", count, runfs.ExpertDir(cfg.RunDir))
	return nil
}

// emitClaimEvents writes one claim_emitted event per CitedFact in
// the hypothesis. claim_id is deterministic so reruns produce
// stable correlation keys (caseID-fact-NNN).
func emitClaimEvents(rec events.Recorder, runID, agentID string, h artifacts.Hypothesis) {
	for i, f := range h.CitedFacts {
		claimID := fmt.Sprintf("%s-fact-%03d", h.CaseID, i+1)
		_ = rec.Emit(events.ClaimEmitted(runID, agentID, h.CaseID, claimID, f.Text, f.Cited))
	}
}

// Citation resolve/flatten helpers were moved to internal/citations
// (citations.ResolveFacts / citations.FlattenFacts) so the verifier
// can use the same primitives without code duplication.

func buildHypothesisLLM(ctx context.Context, client llm.Client, toolAdapter tools.Adapter, repoRoot string, pack artifacts.CasePack, agentID string, temperature float64) (artifacts.Hypothesis, error) {
	toolHits, err := toolAdapter.SearchKeywords(ctx, repoRoot, pack.TargetFiles, append(pack.ExpectedObligations, pack.TargetSymbols...), 8)
	if err != nil {
		return artifacts.Hypothesis{}, err
	}

	system := `You are the Expert Agent in TEECheck. Analyze the bounded case pack and return exactly one JSON object.

Every claim you make about the code MUST be anchored to a specific
range of source bytes. Use the cited_facts field for this — it is
how downstream agents validate that your claims still hold against
the live repo. Claims you cannot anchor are still allowed (use
cited_facts with an empty cited list), but they will be treated as
unverified by the verifier.`
	user := fmt.Sprintf(`Return a JSON object with fields:
- title
- summary
- suspected_issue
- missing_obligations (array of strings)
- cited_facts (array of objects, see below)
- confidence ("low"|"medium"|"high")
- needs_verification (boolean)

cited_facts format — each entry is:
  {
    "text":  "concise claim about the code",
    "cited": [
      { "file": "<repo-relative path>",
        "start_line": <1-indexed inclusive>,
        "end_line":   <1-indexed inclusive, >= start_line> }
    ]
  }

Rules:
- Pick the smallest line range that contains the evidence — do not
  cite an entire file when a 5-line region suffices.
- General citation length cap: aim for ≤30 lines. If you find
  yourself wanting more, ask whether the claim can be split into
  multiple narrower facts each with its own small citation.
- Long-function exception: if the claim genuinely depends on the
  whole function body (e.g. "this 60-line function never validates
  X anywhere"), a wider range is acceptable, but the fact text
  must explicitly say WHY the wider range is needed.
- Absence proofs (claim of form "X is not present in Y"): cite 1-3
  representative lines plus a textual explanation, not the entire
  file. The verifier will trust a focused negative example over a
  100-line "search this whole file yourself" citation.
- Only cite paths that appear in the snippets / tool hits below, or
  that you have other concrete reason to believe exist; the system
  will discard citations whose files cannot be opened.
- One claim may have multiple cited regions if the evidence spans
  separate locations. Prefer multiple small citations over one wide
  citation.
- A fact you cannot anchor: include it with "cited": []. It will be
  flagged as unverified, not silently dropped.

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
		// CitedFacts is the v1.1.1 canonical shape. SupportingFacts
		// is accepted as a transitional fallback for prompt
		// versions that don't ask for cited_facts (e.g. the
		// heuristic path or a model that ignores instructions).
		CitedFacts []citations.CitedFact `json:"cited_facts"`
		SupportingFacts []string `json:"supporting_facts"`
		Confidence         string   `json:"confidence"`
		NeedsVerification  bool     `json:"needs_verification"`
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return artifacts.Hypothesis{}, fmt.Errorf("parse expert json: %w | raw=%s", err, truncate(resp.Text, 400))
	}

	// Resolve every citation against the repo: drop ones that fail,
	// keep the fact text either way. Resolution errors are logged
	// to stdout (not fatal) so a single bad path does not poison
	// the whole hypothesis.
	cleanedFacts, resolveErrors := citations.ResolveFacts(parsed.CitedFacts, repoRoot)
	if len(resolveErrors) > 0 {
		fmt.Printf("[expert] %s: %d citation(s) failed to resolve: %s\n",
			pack.CaseID, len(resolveErrors), strings.Join(resolveErrors, "; "))
	}
	supportingFacts, citedPool := citations.FlattenFacts(cleanedFacts)

	// Back-compat: when the LLM returned legacy supporting_facts
	// instead of cited_facts (older prompts or non-compliant
	// models), fold those strings into SupportingFacts as
	// untyped/unvalidated entries. They will not appear in the
	// CitedFacts list, so consumers can still distinguish them
	// from validated claims.
	if len(parsed.SupportingFacts) > 0 {
		supportingFacts = append(supportingFacts, parsed.SupportingFacts...)
	}
	supportingFacts = append(supportingFacts, flattenToolHits(toolHits)...)

	return artifacts.Hypothesis{
		SchemaVersion:      "teecheck.hypothesis.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		Title:              firstNonEmpty(parsed.Title, fmt.Sprintf("Potential %s weakness in %s", pack.Category, primaryLabel(pack))),
		Summary:            firstNonEmpty(parsed.Summary, "The expert agent found a bounded concern that needs follow-up review."),
		SuspectedIssue:     firstNonEmpty(parsed.SuspectedIssue, pack.Category+" obligations may be incompletely enforced."),
		MissingObligations: uniq(parsed.MissingObligations),
		SupportingFacts:    uniq(supportingFacts),
		CitedFacts:         cleanedFacts,
		Cited:              citedPool,
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
