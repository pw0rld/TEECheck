package challenger

import (
	"context"
	"fmt"
	"strings"

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
- the counter-evidence section below: the Investigator already
  recorded observations AGAINST this issue in THIS repository. Start
  from those rather than re-deriving them, and say explicitly if one
  of them settles the question

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

Counter-evidence the Investigator already found (evidence AGAINST the issue — this is your starting material: confirm it, extend it, or say why it does not hold):
%s

Observed flow (the attack path the Investigator actually traced, in order — the specific chain you are being asked to break):
%s

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
		firstNonEmpty(strings.Join(pack.CounterEvidence, " | "), "(none)"), artifacts.FormatToolPath(pack.ObservedFlow),
		firstNonEmpty(caseCtx.tweText, "(none)"), renderArchitectureSlice(caseCtx.archModel), renderInvariants(caseCtx.invariants),
		renderToolFacts(caseCtx.toolFacts, caseCtx.missingToolFacts),
		formatKnowledgeHints(pack.KnowledgeHints), formatToolHits(toolHits), formatSnippets(pack.Snippets))

	return system, user
}

// buildIndependentViewLLM runs phase 1 against the LLM. Search terms
// for the tool-hit lookup come only from the CasePack (expected
// obligations, required evidence, target symbols) — the
// same "no hypothesis anywhere in this call chain" property
// buildIndependentPrompt has.
//
// The returned adjustments name every value the stage replaced (see
// generateWithRatingRetry); the caller persists them.
func buildIndependentViewLLM(ctx context.Context, client llm.Client, toolAdapter tools.Adapter, repoRoot string, pack artifacts.CasePack, caseCtx caseContext, agentID string, temperature float64) (artifacts.ChallengerIndependentView, []artifacts.NormalizationAdjustment, error) {
	searchTerms := append([]string{}, pack.ExpectedObligations...)
	// RequiredEvidence is the investigation-derived counterpart of
	// ExpectedObligations: the legacy path fills one, the llm path the
	// other, and neither fills both. Without it an llm-path pack searched on
	// TargetSymbols plus the fixed terms below only.
	searchTerms = append(searchTerms, pack.RequiredEvidence...)
	searchTerms = append(searchTerms, pack.TargetSymbols...)
	searchTerms = append(searchTerms, "caller", "bind", "verify", "authorize", "wrapper")
	toolHits, err := toolAdapter.SearchKeywords(ctx, repoRoot, pack.TargetFiles, searchTerms, 8)
	if err != nil {
		return artifacts.ChallengerIndependentView{}, nil, err
	}

	system, user := buildIndependentPrompt(pack, caseCtx, toolHits)

	type phase1Reply struct {
		IssuePresent       bool     `json:"issue_present"`
		Reasoning          string   `json:"reasoning"`
		DefensesConsidered []string `json:"defenses_considered"`
		CounterExamples    []string `json:"counter_examples"`
		Confidence         string   `json:"confidence"`
	}
	// The prompt above asks for "low"|"medium"|"high"; the normalizer
	// below accepts exactly that set and nothing else. When those two
	// lists disagree, every legal answer is silently discarded — which
	// is precisely what happened here for four days.
	parsed, adjustments, err := generateWithRatingRetry(ctx, client, system, user, temperature,
		pack.CaseID, "challenger phase-1",
		ratingSpec[phase1Reply]{
			field:      "confidence",
			vocabulary: confidenceVocabulary,
			normalize:  normalizeConfidence,
			get:        func(r *phase1Reply) string { return r.Confidence },
			set:        func(r *phase1Reply, v string) { r.Confidence = v },
		})
	if err != nil {
		return artifacts.ChallengerIndependentView{}, nil, err
	}

	return artifacts.ChallengerIndependentView{
		SchemaVersion:      "teecheck.challenger_independent.v1",
		CaseID:             pack.CaseID,
		AgentID:            agentID,
		IssuePresent:       parsed.IssuePresent,
		Reasoning:          firstNonEmpty(parsed.Reasoning, "(no reasoning returned)"),
		DefensesConsidered: uniq(parsed.DefensesConsidered),
		CounterExamples:    uniq(parsed.CounterExamples),
		Confidence:         parsed.Confidence,
		KnownLimitations:   []string{knownIndependenceLimitation},
	}, adjustments, nil
}

// knownIndependenceLimitation is §7.7's disclosed caveat: the
// ToolFacts phase 1 sees were themselves selected by the earlier
// Expert/Planner investigation, so this is independence-of-conclusion
// (the Challenger did not read the Expert's hypothesis text), not
// independence-of-evidence-selection. Recorded on every
// ChallengerIndependentView so it travels with the artifact rather
// than living only in a doc comment.
const knownIndependenceLimitation = "phase-1 ToolFacts were selected by the Expert/Planner's earlier investigation; this is independence of conclusion, not independence of evidence selection (§7.7)"

