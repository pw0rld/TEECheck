package challenger

import (
	"context"
	"fmt"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/tools"
)

// Phase 1 (§7.7, §25): the Challenger's independent judgment. The
// defining constraint of this file is structural, not a prompt
// instruction: buildIndependentPrompt's signature has no
// artifacts.Hypothesis parameter anywhere in its call chain, so there
// is no value it could interpolate into the prompt even if someone
// tried. internal/challenger/phase1_test.go asserts this on the
// actually-assembled prompt string, not just on the function
// signature, so a future refactor that threaded the hypothesis
// through some other channel (a closure, a package-level var) would
// still be caught.

// buildIndependentPrompt assembles the phase-1 system/user prompt
// from ONLY: the CasePack, its loaded caseContext (TWE knowledge,
// architecture slice, invariants, tool facts), and phase-1 tool hits
// searched using CasePack-derived terms. No Hypothesis type appears
// in this function's signature.
func buildIndependentPrompt(pack artifacts.CasePack, caseCtx caseContext, toolHits []tools.SearchHit) (system, user string) {
	system = `You are the Challenger Agent in TEECheck, running phase 1 of a two-phase review (§7.7, §25). You have NOT been shown any other agent's conclusion — form your own independent judgment from the evidence below.

Check specifically for:
- outer or lower-layer guards that might already handle this (a
  wrapper, a caller, a lower protocol/transport layer, an external
  service)
- whether a version/state value actually propagates through a
  DIFFERENT structure than the one visible in this snippet
- whether the obligation only applies in test, debug, config, or
  deployment-specific scope (i.e. this code path may not even be the
  one that runs in production)
- downstream freshness or rollback protection that might catch what
  this snippet misses
- the TWE's own common_defenses and common_false_positives lists —
  if the visible code matches one of those patterns, say so

Return exactly one JSON object with fields:
- issue_present (boolean)
- reasoning (string)
- defenses_considered (array of strings — wrapper/lower-layer/external
  protections and TWE common_defenses/common_false_positives you
  checked, whether or not they applied)
- counter_examples (array of strings — alternative explanations a
  tool call could verify, e.g. "grep for a caller that validates this
  before invoking")
- confidence ("low"|"medium"|"high")`

	user = fmt.Sprintf(`Case:
- case_id: %s
- category: %s
- priority: %s
- target_files: %s
- target_symbols: %s
- expected_obligations: %s
- related_twes: %s
- common_defenses: %s
- common_false_positives: %s
- required_evidence: %s
- missing_links: %s
- coverage_gaps: %s
- open_questions: %s

TWE prior knowledge:
%s

Architecture slice (project-specific; from the Architecture Agent):
%s

Project Invariants relevant to this case:
%s

ToolFacts referenced by this case (immutable — cite by fact_id, do not restate as your own finding):
%s

Knowledge hints:
%s

Tool hits (searched using case-pack terms only):
%s

Snippets (the raw source this case is about):
%s
`, pack.CaseID, pack.Category, pack.Priority, strings.Join(pack.TargetFiles, ", "), strings.Join(pack.TargetSymbols, ", "),
		strings.Join(pack.ExpectedObligations, ", "), strings.Join(pack.RelatedTWEs, ", "),
		strings.Join(pack.CommonDefenses, " | "), strings.Join(pack.CommonFalsePositives, " | "),
		strings.Join(pack.RequiredEvidence, " | "), strings.Join(pack.MissingLinks, " | "), strings.Join(pack.CoverageGaps, " | "),
		strings.Join(pack.OpenQuestions, " | "),
		firstNonEmpty(caseCtx.tweText, "(none)"), renderArchitectureSlice(caseCtx.archModel), renderInvariants(caseCtx.invariants),
		renderToolFacts(caseCtx.toolFacts, caseCtx.missingToolFacts),
		formatKnowledgeHints(pack.KnowledgeHints), formatToolHits(toolHits), formatSnippets(pack.Snippets))

	return system, user
}

// buildIndependentViewLLM runs phase 1 against the LLM. Search terms
// for the tool-hit lookup come only from the CasePack (expected
// obligations, target symbols, common defenses/false positives) — the
// same "no hypothesis anywhere in this call chain" property
// buildIndependentPrompt has.
func buildIndependentViewLLM(ctx context.Context, client llm.Client, toolAdapter tools.Adapter, repoRoot string, pack artifacts.CasePack, caseCtx caseContext, agentID string, temperature float64) (artifacts.ChallengerIndependentView, error) {
	searchTerms := append([]string{}, pack.ExpectedObligations...)
	searchTerms = append(searchTerms, pack.TargetSymbols...)
	searchTerms = append(searchTerms, "caller", "bind", "verify", "authorize", "wrapper")
	toolHits, err := toolAdapter.SearchKeywords(ctx, repoRoot, pack.TargetFiles, searchTerms, 8)
	if err != nil {
		return artifacts.ChallengerIndependentView{}, err
	}

	system, user := buildIndependentPrompt(pack, caseCtx, toolHits)
	resp, err := client.Generate(ctx, llm.GenerateRequest{
		SystemPrompt: system,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		Temperature:  temperature,
		JSONMode:     true,
	})
	if err != nil {
		return artifacts.ChallengerIndependentView{}, err
	}

	var parsed struct {
		IssuePresent       bool     `json:"issue_present"`
		Reasoning          string   `json:"reasoning"`
		DefensesConsidered []string `json:"defenses_considered"`
		CounterExamples    []string `json:"counter_examples"`
		Confidence         string   `json:"confidence"`
	}
	if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
		return artifacts.ChallengerIndependentView{}, fmt.Errorf("parse challenger phase-1 json: %w | raw=%s", err, truncate(resp.Text, 400))
	}

	return artifacts.ChallengerIndependentView{
		SchemaVersion:      "teecheck.challenger_independent.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		IssuePresent:       parsed.IssuePresent,
		Reasoning:          firstNonEmpty(parsed.Reasoning, "(no reasoning returned)"),
		DefensesConsidered: uniq(parsed.DefensesConsidered),
		CounterExamples:    uniq(parsed.CounterExamples),
		Confidence:         normalizeExploitability(parsed.Confidence, ""),
		KnownLimitations:   []string{knownIndependenceLimitation},
	}, nil
}

// knownIndependenceLimitation is §7.7's disclosed caveat: the
// ToolFacts phase 1 sees were themselves selected by the earlier
// Expert/Planner investigation, so this is independence-of-conclusion
// (the Challenger did not read the Expert's hypothesis text), not
// independence-of-evidence-selection. Recorded on every
// ChallengerIndependentView so it travels with the artifact rather
// than living only in a doc comment.
const knownIndependenceLimitation = "phase-1 ToolFacts were selected by the Expert/Planner's earlier investigation; this is independence of conclusion, not independence of evidence selection (§7.7)"

// buildIndependentViewHeuristic is the non-LLM phase-1 path. It
// reasons only over signals already present in the CasePack — an
// explicit unfinished-code marker suggests an issue; a snippet that
// appears to reference one of the case's own expected_obligations (a
// call site, a check) suggests a defense is present. Neither
// fabricates evidence; a case with no textual signal either way falls
// back to the Investigator's own MissingLinks flag rather than
// guessing.
func buildIndependentViewHeuristic(pack artifacts.CasePack, agentID string) artifacts.ChallengerIndependentView {
	var markerNotes []string
	var defenses []string
	sawMarker := false
	sawObligationSignal := false

	for _, snippet := range pack.Snippets {
		lower := strings.ToLower(snippet.Content)
		if strings.Contains(lower, "todo") || strings.Contains(lower, "missing") || strings.Contains(lower, "fixme") {
			sawMarker = true
			markerNotes = append(markerNotes, fmt.Sprintf("snippet %s contains an explicit unfinished marker", snippet.Path))
		}
		for _, ob := range pack.ExpectedObligations {
			ob = strings.TrimSpace(ob)
			if ob == "" {
				continue
			}
			if strings.Contains(lower, strings.ToLower(ob)) {
				sawObligationSignal = true
				defenses = append(defenses, fmt.Sprintf("snippet %s appears to reference the expected obligation %q", snippet.Path, ob))
			}
		}
		for _, defense := range pack.CommonDefenses {
			kw := strings.ToLower(strings.TrimSpace(defense))
			if kw != "" && strings.Contains(lower, kw) {
				sawObligationSignal = true
				defenses = append(defenses, fmt.Sprintf("snippet %s matches a common defense pattern: %s", snippet.Path, defense))
			}
		}
	}

	var issuePresent bool
	var reasoning string
	switch {
	case sawMarker:
		issuePresent = true
		reasoning = "explicit unfinished-code marker found in the case's own snippets"
	case sawObligationSignal:
		issuePresent = false
		reasoning = "the case's snippets appear to reference the expected obligation or a known common defense"
	default:
		// No textual signal either way: fall back to what the
		// Investigator already flagged, rather than guessing.
		issuePresent = len(pack.MissingLinks) > 0
		if issuePresent {
			reasoning = "no direct textual signal; the Investigator's own missing_links flag the obligation as unresolved"
		} else {
			reasoning = "no direct textual signal and no outstanding missing_links; independent review cannot confirm an issue"
		}
	}

	confidence := "low"
	if sawMarker || sawObligationSignal {
		confidence = "medium"
	}

	// Tool-verifiable counter-examples (§7.7): generic, deterministic
	// checks a downstream tool call could actually run, plus the
	// explicit unfinished-marker notes as concrete anchors.
	counterExamples := append([]string{}, markerNotes...)
	counterExamples = append(counterExamples,
		"grep for a caller that validates this before invoking",
		"confirm whether the failure path actually stops execution rather than logging and continuing")

	return artifacts.ChallengerIndependentView{
		SchemaVersion:      "teecheck.challenger_independent.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		IssuePresent:       issuePresent,
		Reasoning:          reasoning,
		DefensesConsidered: uniq(append(defenses, pack.CommonFalsePositives...)),
		CounterExamples:    uniq(counterExamples),
		Confidence:         confidence,
		KnownLimitations:   []string{knownIndependenceLimitation},
	}
}
