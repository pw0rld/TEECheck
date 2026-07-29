package arbiter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// taggedJoin formats an untyped string list with a per-item tag
// for inclusion in LLM prompts. Empty list → "(none)" so the LLM
// sees an explicit signal instead of an empty placeholder.
func taggedJoin(items []string, tag string) string {
	if len(items) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, tag+" "+it)
	}
	return strings.Join(parts, " | ")
}

func buildPacket(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo, item artifacts.FindingItem, sections artifacts.ArbiterSections) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Review Packet: %s\n\n", pack.CaseID))
	b.WriteString(fmt.Sprintf("- Category: `%s`\n", pack.Category))
	b.WriteString(fmt.Sprintf("- Priority: `%s`\n", pack.Priority))
	b.WriteString(fmt.Sprintf("- Arbiter Status: `%s`\n", item.Status))
	b.WriteString(fmt.Sprintf("- Confidence: `%s`\n\n", item.Confidence))

	// §7.9/§25: the eight clearly-separated sections, rendered first
	// so a reviewer sees the aggregated evidence before the prose
	// hypothesis/challenge/verification narrative below (kept for
	// backward-compat with existing packet consumers).
	b.WriteString("## Anchored ToolFacts\n\n")
	writeBulletsOrNone(&b, sections.AnchoredToolFacts)
	b.WriteString("\n## Architecture Evidence Status\n\n")
	writeBulletsOrNone(&b, sections.ArchitectureEvidenceStatus)
	b.WriteString("\n## Invariant Verification Status\n\n")
	writeBulletsOrNone(&b, sections.InvariantVerificationStatus)
	b.WriteString("\n## Expert Hypothesis (aggregated)\n\n")
	b.WriteString(sections.ExpertHypothesis)
	b.WriteString("\n\n## Independent Challenger Result\n\n")
	b.WriteString(sections.IndependentChallengerResult)
	b.WriteString("\n\n## Verifier Resolution (aggregated)\n\n")
	b.WriteString(sections.VerifierResolution)
	b.WriteString("\n\n## Remaining Coverage Gaps\n\n")
	writeBulletsOrNone(&b, sections.RemainingCoverageGaps)
	b.WriteString("\n## Human Review Questions\n\n")
	writeBulletsOrNone(&b, sections.HumanReviewQuestions)
	b.WriteString("\n")

	b.WriteString("## Hypothesis\n\n")
	b.WriteString(fmt.Sprintf("- Title: %s\n", hypothesis.Title))
	b.WriteString(fmt.Sprintf("- Summary: %s\n", hypothesis.Summary))
	b.WriteString(fmt.Sprintf("- Missing obligations: %s\n", strings.Join(hypothesis.MissingObligations, ", ")))
	if len(hypothesis.SupportingFacts) > 0 {
		b.WriteString("- Supporting facts (anchored):\n")
		for _, item := range hypothesis.SupportingFacts {
			b.WriteString(fmt.Sprintf("  - %s\n", item))
		}
	}
	if len(hypothesis.UntypedFacts) > 0 {
		b.WriteString("- Unanchored context (tool hits / legacy text — not citation-backed):\n")
		for _, item := range hypothesis.UntypedFacts {
			b.WriteString(fmt.Sprintf("  - [unanchored] %s\n", item))
		}
	}
	b.WriteString("\n")
	b.WriteString("## Challenger View\n\n")
	b.WriteString(fmt.Sprintf("- Exploitability: %s\n", artifacts.FormatRating(challenge.Exploitability)))
	b.WriteString(fmt.Sprintf("- Narrative: %s\n", challenge.ExploitNarrative))
	if len(challenge.CounterArguments) > 0 {
		b.WriteString("- Counter-arguments:\n")
		for _, item := range challenge.CounterArguments {
			b.WriteString(fmt.Sprintf("  - %s\n", item))
		}
	}
	b.WriteString("\n## Verification\n\n")
	b.WriteString(fmt.Sprintf("- Status: %s\n", memo.Status))
	if len(memo.ConfirmedFacts) > 0 {
		b.WriteString("- Confirmed facts:\n")
		for _, item := range memo.ConfirmedFacts {
			b.WriteString(fmt.Sprintf("  - %s\n", item))
		}
	}
	if len(memo.Contradictions) > 0 {
		b.WriteString("- Contradictions:\n")
		for _, item := range memo.Contradictions {
			b.WriteString(fmt.Sprintf("  - %s\n", item))
		}
	}
	if len(memo.UntypedConfirmedFacts) > 0 {
		b.WriteString("- Unanchored confirmed (verifier returned legacy text without citations):\n")
		for _, item := range memo.UntypedConfirmedFacts {
			b.WriteString(fmt.Sprintf("  - [unanchored] %s\n", item))
		}
	}
	if len(memo.UntypedContradictions) > 0 {
		b.WriteString("- Unanchored contradictions (verifier returned legacy text without citations):\n")
		for _, item := range memo.UntypedContradictions {
			b.WriteString(fmt.Sprintf("  - [unanchored] %s\n", item))
		}
	}
	b.WriteString("\n## Knowledge Hints\n\n")
	for _, hint := range pack.KnowledgeHints {
		b.WriteString(fmt.Sprintf("- %s: %s\n", hint.Title, hint.Reason))
	}
	return b.String()
}

// writeBulletsOrNone renders a "- item" line per entry, or a single
// "- (none)" line when the list is empty — an explicit "nothing here"
// marker rather than a silently blank section, matching the
// convention taggedJoin/formatKnowledgeHints already use elsewhere in
// this package.
func writeBulletsOrNone(b *strings.Builder, items []string) {
	if len(items) == 0 {
		b.WriteString("- (none)\n")
		return
	}
	for _, item := range items {
		fmt.Fprintf(b, "- %s\n", item)
	}
}

func severityForCategory(category string) string {
	switch category {
	case "attestation", "authorization", "key_management":
		return "high"
	case "state_machine", "boundary":
		return "medium"
	default:
		return "medium"
	}
}

func RunWithBus(cfg config.Config, client llm.Client, bus *agentbus.Bus) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	findings := artifacts.Findings{
		SchemaVersion: "teecheck.findings.v2",
		RunID:         manifest.RunID,
	}
	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack: %w", err)
		}
		var hypothesis artifacts.Hypothesis
		if err := runfs.ReadJSON(filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1)), &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis: %w", err)
		}
		var challenge artifacts.Challenge
		if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1)), &challenge); err != nil {
			return fmt.Errorf("read challenge: %w", err)
		}
		var memo artifacts.VerificationMemo
		if err := runfs.ReadJSON(filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1)), &memo); err != nil {
			return fmt.Errorf("read verification memo: %w", err)
		}

		caseCtx := loadCaseContext(cfg.RunDir, pack)
		independentView := loadIndependentView(challenge.IndependentViewPath)

		bus.ResetDialog(pack.CaseID)
		item, packet, err := arbitrateLLM(context.Background(), client, bus, pack, hypothesis, challenge, memo, caseCtx, independentView, cfg.AgentID, cfg.LLMTemp)
		if err != nil {
			return fmt.Errorf("arbiter llm for %s: %w", pack.CaseID, err)
		}

		if cfg.MaxFindings == 0 || len(findings.Findings) < cfg.MaxFindings {
			findings.Findings = append(findings.Findings, item)
		}
		packetPath := filepath.Join(runfs.ArbiterPacketsDir(cfg.RunDir), fmt.Sprintf("review-%03d.md", idx+1))
		if err := runfs.WriteText(packetPath, packet); err != nil {
			return fmt.Errorf("write arbiter packet: %w", err)
		}

		if dialog := bus.GetDialog(pack.CaseID); dialog != nil && len(dialog.Rounds) > 0 {
			dialogPath := filepath.Join(runfs.ArbiterDir(cfg.RunDir), fmt.Sprintf("dialog-%03d.jsonl", idx+1))
			if err := writeDialogJSONL(dialogPath, dialog); err != nil {
				fmt.Printf("Warning: failed to write arbiter dialog: %v\n", err)
			}
		}
		count++
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(cfg.RunDir), findings); err != nil {
		return fmt.Errorf("write arbiter findings: %w", err)
	}
	fmt.Printf("Wrote %d arbiter packet(s) to %s\n", count, runfs.ArbiterDir(cfg.RunDir))
	return nil
}

func arbitrateLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo, caseCtx caseContext, independent artifacts.ChallengerIndependentView, agentID string, temperature float64) (artifacts.FindingItem, string, error) {
	complete := attackChainComplete(pack, hypothesis, memo)

	systemPrompt := `You are the Arbiter Agent in TEECheck. Aggregate — do not re-analyze the whole repo — the Expert hypothesis, the Challenger's independent phase-1 result and phase-2 differences, the Verifier's resolution, and the anchored ToolFacts/Architecture/Invariant evidence into a final judgment and human-readable review packet.

Return a JSON object with fields:
- status: "no_issue_observed" | "needs_review" | "likely_issue" | "confirmed_candidate"
- severity: "high" | "medium" | "low"
- confidence: "high" | "medium" | "low"
- summary: string
- evidence: array of strings
- review_packet_markdown: string (full review packet in markdown)
- queries: array of objects (optional, each with: to_agent, kind, question)

CRITICAL RULE (§25): the attack chain for this case is currently
reported as "attack_chain_complete: %v" below. If it is false, you
MUST NOT use the status "confirmed_candidate" or the phrase
"confirmed vulnerability" anywhere in summary/evidence/review_packet_markdown
— use "likely_issue" or "needs_review" and describe the specific gap
instead. This is checked mechanically after your response is parsed;
violating it will have your output rewritten, so follow it directly.`

	userMsg := fmt.Sprintf(`Case: %s (category: %s, priority: %s)
Files: %s
attack_chain_complete: %v (%s)

Expert hypothesis:
- Title: %s
- Suspected issue: %s
- Classification: %s
- Confidence: %s
- Supporting facts (validated, citation-anchored): %s
- Unanchored expert context (tool hits or legacy text — NOT
  citation-backed; do not treat as evidence on its own): %s

Independent Challenger result (phase 1, formed WITHOUT the Expert hypothesis):
- issue_present: %v
- reasoning: %s
- key_differences vs. Expert hypothesis: %s
- Exploitability: %s
- Stance: %s
- Counter arguments: %s

Verifier resolution:
- Status: %s
- Confirmed facts (validated, citation-anchored): %s
- Contradictions (validated, citation-anchored): %s
- Unanchored verifier confirmations (legacy text without citations): %s
- Unanchored verifier contradictions (legacy text without citations): %s
- Evidence distinctions (not-found vs proven-absent): %s
- Invariant status updates proposed (NOT yet applied to the stored artifact): %s

Observed flow (the attack path the Investigator actually traced, in order — this is the chain attack_chain_complete above refers to):
%s

Counter-evidence the Investigator already found (evidence AGAINST this case — a judgment that does not account for it is not an aggregation of the evidence):
%s

Anchored ToolFacts:
%s

Architecture evidence status:
%s

Knowledge hints:
%s

When you write evidence and the review packet, treat unanchored
items as supporting context only — they MAY be true but are not
citation-validated. Validated items are the basis for any
"likely_issue" or "confirmed_candidate" verdict.`,
		pack.CaseID, pack.Category, pack.Priority,
		strings.Join(pack.TargetFiles, ", "),
		complete, chainCompletenessNote(pack, hypothesis, memo, complete),
		hypothesis.Title, hypothesis.SuspectedIssue, firstNonEmptyStr(hypothesis.Classification, "(unclassified)"), hypothesis.Confidence,
		strings.Join(hypothesis.SupportingFacts, " | "),
		taggedJoin(hypothesis.UntypedFacts, "[unanchored]"),
		independent.IssuePresent, independent.Reasoning, strings.Join(orNone(challenge.KeyDifferences), " | "),
		artifacts.FormatRating(challenge.Exploitability), challenge.ReviewerStance,
		strings.Join(challenge.CounterArguments, " | "),
		memo.Status,
		strings.Join(memo.ConfirmedFacts, " | "),
		strings.Join(memo.Contradictions, " | "),
		taggedJoin(memo.UntypedConfirmedFacts, "[unanchored]"),
		taggedJoin(memo.UntypedContradictions, "[unanchored]"),
		formatEvidenceDistinctionsForLLM(memo.EvidenceDistinctions),
		formatInvariantUpdatesForLLM(memo.InvariantUpdates),
		artifacts.FormatToolPath(pack.ObservedFlow), taggedJoin(pack.CounterEvidence, "-"),
		taggedJoin(renderAnchoredToolFacts(caseCtx), "-"),
		taggedJoin(renderArchitectureEvidenceStatus(caseCtx.archModel), "-"),
		formatKnowledgeHintsForLLM(pack.KnowledgeHints))
	systemPrompt = fmt.Sprintf(systemPrompt, complete)

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		var parsed struct {
			Status               string   `json:"status"`
			Severity             string   `json:"severity"`
			Confidence           string   `json:"confidence"`
			Summary              string   `json:"summary"`
			Evidence             []string `json:"evidence"`
			ReviewPacketMarkdown string   `json:"review_packet_markdown"`
			Queries              []struct {
				ToAgent  string `json:"to_agent"`
				Kind     string `json:"kind"`
				Question string `json:"question"`
			} `json:"queries"`
		}
		// llm.GenerateJSON re-asks once if the reply is not a JSON object; a
		// single format wobble no longer costs the whole case. The response it
		// returns is the one that actually parsed, so the assistant turn
		// appended to the dialog below is the recovered reply, not the
		// rejected one. See its doc comment for the bound.
		resp, err := llm.GenerateJSON(ctx, client, "arbiter", llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
			JSONMode:     true,
		}, &parsed)
		if err != nil {
			return artifacts.FindingItem{}, "", err
		}

		if len(parsed.Queries) == 0 {
			// Always append untyped items to Evidence with explicit
			// [unanchored ...] tags. The LLM may have reasoned over
			// the untyped fields when writing parsed.Evidence, but
			// we cannot rely on it; appending here guarantees that
			// every untyped artifact item shows up in the finding's
			// Evidence list at least once, distinguishable from the
			// LLM's own validated picks.
			evidence := append([]string{}, parsed.Evidence...)
			for _, u := range hypothesis.UntypedFacts {
				evidence = append(evidence, "[unanchored] "+u)
			}
			for _, u := range memo.UntypedConfirmedFacts {
				evidence = append(evidence, "[unanchored verifier confirm] "+u)
			}
			for _, u := range memo.UntypedContradictions {
				evidence = append(evidence, "[unanchored verifier contradict] "+u)
			}
			sections := buildSections(pack, hypothesis, challenge, memo, caseCtx, independent)
			item := artifacts.FindingItem{
				FindingID:  pack.CaseID,
				SliceID:    pack.CaseID,
				Status:     parsed.Status,
				Severity:   parsed.Severity,
				Confidence: parsed.Confidence,
				Files:      pack.TargetFiles,
				Summary:    parsed.Summary,
				Evidence:   evidence,
				Sections:   &sections,
			}
			// §25 mechanical gate applies to the LLM path too: a
			// model that ignores the prompt's CRITICAL RULE and
			// writes "confirmed_candidate"/"confirmed vulnerability"
			// anyway still gets rewritten here.
			item = sanitizeFindingItem(item, complete)

			packet := parsed.ReviewPacketMarkdown
			if packet == "" {
				packet = buildPacket(pack, hypothesis, challenge, memo, item, sections)
			} else if !complete {
				// Same mechanical scrub as the structured fields —
				// applied to the LLM's own free-text packet so a
				// model that ignored the CRITICAL RULE cannot smuggle
				// the forbidden phrase through the markdown field.
				packet = scrubConfirmedWording(packet)
			}
			return item, packet, nil
		}

		var queryResults []string
		for i, q := range parsed.Queries {
			busResp, err := bus.AskForCase(ctx, pack.CaseID, agentbus.Query{
				QueryID:   fmt.Sprintf("arbiter-%s-r%d-q%d", pack.CaseID, round, i),
				FromAgent: agentID,
				ToAgent:   q.ToAgent,
				Kind:      q.Kind,
				Question:  q.Question,
			})
			if err != nil {
				queryResults = append(queryResults, fmt.Sprintf("Query to %s failed: %v", q.ToAgent, err))
				continue
			}
			queryResults = append(queryResults, fmt.Sprintf("Response from %s: %s\nFacts: %s", busResp.FromAgent, busResp.Answer, strings.Join(busResp.Facts, "; ")))
		}

		followUp := fmt.Sprintf("Here are the responses to your queries:\n%s\n\nNow provide your final judgment.", strings.Join(queryResults, "\n\n"))
		messages = append(messages, llm.Message{Role: "assistant", Content: resp.Text})
		messages = append(messages, llm.Message{Role: "user", Content: followUp})
	}

	sections := buildSections(pack, hypothesis, challenge, memo, caseCtx, independent)
	item := artifacts.FindingItem{
		FindingID:  pack.CaseID,
		SliceID:    pack.CaseID,
		Status:     "needs_review",
		Severity:   severityForCategory(pack.Category),
		Confidence: "low",
		Files:      pack.TargetFiles,
		Summary:    "Reached maximum dialog rounds without final arbiter judgment",
		Sections:   &sections,
	}
	return item, buildPacket(pack, hypothesis, challenge, memo, item, sections), nil
}

func formatEvidenceDistinctionsForLLM(notes []artifacts.EvidenceDistinctionNote) string {
	if len(notes) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, n := range notes {
		lines = append(lines, fmt.Sprintf("  - [%s] %s (%s)", n.Outcome, n.Claim, n.Note))
	}
	return strings.Join(lines, "\n")
}

func formatInvariantUpdatesForLLM(updates []artifacts.InvariantStatusUpdate) string {
	if len(updates) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, u := range updates {
		lines = append(lines, fmt.Sprintf("  - %s: %s -> %s (%s)", u.InvariantID, u.PreviousStatus, u.NewStatus, u.Reason))
	}
	return strings.Join(lines, "\n")
}

func formatKnowledgeHintsForLLM(hints []artifacts.KnowledgeHint) string {
	if len(hints) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, h := range hints {
		lines = append(lines, fmt.Sprintf("  - %s: %s", h.Title, h.Reason))
	}
	return strings.Join(lines, "\n")
}

func writeDialogJSONL(path string, dialog *agentbus.Dialog) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, round := range dialog.Rounds {
		if err := enc.Encode(round); err != nil {
			return err
		}
	}
	return nil
}
