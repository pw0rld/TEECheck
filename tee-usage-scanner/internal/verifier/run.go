package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/citations"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/events"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
)

func parseStaticTools(value string) []string {
	if value == "" || strings.EqualFold(value, "auto") {
		return []string{"grep"}
	}
	if strings.EqualFold(value, "none") {
		return nil
	}
	var tools []string
	for _, t := range strings.Split(value, ",") {
		t = strings.TrimSpace(strings.ToLower(t))
		if t != "" {
			tools = append(tools, t)
		}
	}
	return tools
}

// RunWithBus is the standalone entry point used by `teecheck verifier`
// when invoked manually. Delegates to RunWithBusAndEvents with no
// event sink so manual reruns don't pollute an events.jsonl owned
// by another process.
func RunWithBus(cfg config.Config, client llm.Client, bus *agentbus.Bus) error {
	return RunWithBusAndEvents(cfg, client, bus, nil)
}

// RunWithBusAndEvents is the pipeline-facing entry point. The
// recorder, when non-nil, receives one claim_emitted event per
// CitedFact the verifier produces (both confirmed and contradicted)
// so downstream consumers can correlate verifier claims with the
// expert hypothesis they were judging.
func RunWithBusAndEvents(cfg config.Config, client llm.Client, bus *agentbus.Bus, rec events.Recorder) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	reg := scall.NewDefaultRegistry()
	enabledTools := parseStaticTools(cfg.StaticTools)

	count := 0
	for idx, casePath := range casePaths {
		var pack artifacts.CasePack
		if err := runfs.ReadJSON(casePath, &pack); err != nil {
			return fmt.Errorf("read case pack %s: %w", casePath, err)
		}
		var hypothesis artifacts.Hypothesis
		if err := runfs.ReadJSON(filepath.Join(runfs.ExpertDir(cfg.RunDir), fmt.Sprintf("hypothesis-%03d.json", idx+1)), &hypothesis); err != nil {
			return fmt.Errorf("read hypothesis: %w", err)
		}
		var challenge artifacts.Challenge
		if err := runfs.ReadJSON(filepath.Join(runfs.ChallengerDir(cfg.RunDir), fmt.Sprintf("challenge-%03d.json", idx+1)), &challenge); err != nil {
			return fmt.Errorf("read challenge: %w", err)
		}

		// PR-07 (§7.8, §25): see the parallel comment in Run() above.
		caseCtx := loadCaseContext(cfg.RunDir, pack)

		var scFindings []staticcheck.CheckFinding
		if enabledTools != nil {
			req := staticcheck.CheckRequest{
				RepoRoot:    manifest.LocalPath,
				TargetFiles: pack.TargetFiles,
				Keywords:    disputeDrivenKeywords(pack, challenge, caseCtx.invariants),
				Category:    pack.Category,
			}
			for _, toolName := range enabledTools {
				results, err := reg.RunByName(context.Background(), toolName, req)
				if err != nil {
					fmt.Printf("Warning: static check %s failed: %v\n", toolName, err)
					continue
				}
				scFindings = append(scFindings, results...)
			}
		}

		// Validate expert's citations against the live repo BEFORE
		// the verifier LLM sees them. Each expert fact is tagged
		// valid / stale / unanchored / unresolved; the LLM gets the
		// tags so it can weight expert claims accordingly.
		expertValidation := citations.ValidateFacts(hypothesis.CitedFacts, manifest.LocalPath)

		bus.ResetDialog(pack.CaseID)
		memo, err := buildMemoLLM(context.Background(), client, bus, manifest.LocalPath, pack, hypothesis, challenge, caseCtx, cfg.AgentID, cfg.LLMTemp, scFindings, expertValidation)
		if err != nil {
			return fmt.Errorf("verifier llm for %s: %w", pack.CaseID, err)
		}
		memo.ExpertCitationValidation = expertValidation
		memo.EvidenceDistinctions = computeEvidenceDistinctions(caseCtx, enabledTools != nil, scFindings)
		memo.ArchitectureChecks = renderArchitectureChecks(caseCtx.archModel)
		memo.InvariantChecks = renderInvariantChecks(caseCtx.invariants)
		memo.InvariantUpdates = computeInvariantUpdates(caseCtx.invariants, memo.Status)
		if err := appendInvariantUpdates(cfg.RunDir, pack.CaseID, memo.InvariantUpdates); err != nil {
			fmt.Printf("Warning: failed to append invariant status updates for %s: %v\n", pack.CaseID, err)
		}

		target := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, memo); err != nil {
			return fmt.Errorf("write verification memo: %w", err)
		}

		// Emit one claim_emitted event per cited fact the verifier
		// produced, so downstream replay / stats can correlate
		// verifier claims with expert claims by case_id + agent.
		if rec != nil {
			emitVerifierClaimEvents(rec, manifest.RunID, cfg.AgentID, memo)
		}

		if dialog := bus.GetDialog(pack.CaseID); dialog != nil && len(dialog.Rounds) > 0 {
			dialogPath := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("dialog-%03d.jsonl", idx+1))
			if err := writeDialogJSONL(dialogPath, dialog); err != nil {
				fmt.Printf("Warning: failed to write dialog: %v\n", err)
			}
		}
		count++
	}
	fmt.Printf("Wrote %d verification memo(s) to %s\n", count, runfs.VerifierDir(cfg.RunDir))
	return nil
}

func buildMemoLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, repoRoot string, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, caseCtx caseContext, agentID string, temperature float64, scFindings []staticcheck.CheckFinding, expertValidation []citations.CitationValidation) (artifacts.VerificationMemo, error) {
	systemPrompt := `You are the Verifier Agent in TEECheck. Analyze static check results and code evidence to arbitrate between the Expert's hypothesis and the Challenger's independent (phase-1) view and phase-2 differences.

Turn the dispute between the Expert and Challenger into concrete tool
questions: a fact-layer call, a reverse trace, a grep, or a citation
check. You may also challenge an architecture statement or invariant
assumption the dispute depends on if its evidence state is inferred,
documented, or unknown rather than observed. Distinguish "we searched
and found nothing" from "a tool proved this is absent" — do not
conflate the two.

Return a JSON object with fields:
- status: "corroborated" | "contested" | "inconclusive"
- checks_run: array of strings
- confirmed_cited_facts: array of {text, cited:[{file, start_line, end_line}]}
- contradicted_cited_facts: array of {text, cited:[{file, start_line, end_line}]}
- confirmed_facts: array of strings (legacy text-only — prefer confirmed_cited_facts)
- contradictions:  array of strings (legacy text-only — prefer contradicted_cited_facts)
- notes: array of strings
- queries: array of objects (optional, each with: to_agent, kind, question)

Citation rules (same as expert):
- Every confirmed or contradicted fact MUST be anchored to specific
  source bytes via cited[]. Pick the smallest line range that
  contains the evidence.
- Only cite paths that appear in the snippets below; the system will
  drop citations whose files cannot be opened.
- If you cannot anchor a fact, include it with cited: [] — it will
  be flagged unverified, not silently dropped.

When the user prompt includes an "EXPERT CITATION STATUS" section,
treat each expert fact according to its tag:
  [valid]      the cited bytes still match — claim is anchored
  [stale]      cited bytes drifted — the specific evidence the
               expert attached has moved or changed; do not treat
               the claim as proven, but the underlying issue may
               still be real
  [unanchored] expert asserted without producing bytes; treat as
               unverified and demand evidence before corroborating
  [unresolved] live repo not available; you cannot verify; note
               this in your output rather than guessing`

	userMsg := fmt.Sprintf(`Case: %s (category: %s, priority: %s)
Target files: %s
Target symbols: %s

Expert hypothesis:
- Title: %s
- Suspected issue: %s
- Missing obligations: %s
- Supporting facts (validated, citation-anchored): %s
- Untyped context (UNVALIDATED — tool hits or legacy text the
  expert did not cite; treat as background, not as evidence): %s
- Confidence: %s

EXPERT CITATION STATUS (validated against the live repo at the moment you began review):
%s

Challenger view:
- Independent (phase-1, formed without the Expert hypothesis) issue_present: %v
- Key differences between the independent view and the Expert hypothesis: %s
- Exploitability: %s
- Narrative: %s
- Counter arguments: %s
- Remaining questions: %s

Observed flow (the attack path the Investigator actually traced, in order — check the disputed step against the source below, do not re-derive the path):
%s

Counter-evidence the Investigator already found (evidence AGAINST this case — resolve it explicitly; corroborating a case whose counter-evidence you never addressed is how a false positive survives review):
%s

TWE prior knowledge:
%s

Architecture slice (project-specific; from the Architecture Agent):
%s

Project Invariants relevant to this case:
%s

ToolFacts referenced by this case (immutable — cite by fact_id, do not restate as your own finding):
%s

Source code snippets from the case pack (you MUST re-ground your judgment against this actual code, not just the summaries above):
%s

Static check findings (%d total):
%s`,
		pack.CaseID, pack.Category, pack.Priority,
		strings.Join(pack.TargetFiles, ", "),
		strings.Join(pack.TargetSymbols, ", "),
		hypothesis.Title, hypothesis.SuspectedIssue,
		strings.Join(hypothesis.MissingObligations, ", "),
		strings.Join(hypothesis.SupportingFacts, " | "),
		formatUntypedFacts(hypothesis.UntypedFacts),
		hypothesis.Confidence,
		formatExpertCitationStatus(expertValidation),
		challenge.IndependentIssuePresent, strings.Join(challenge.KeyDifferences, " | "),
		artifacts.FormatRating(challenge.Exploitability), challenge.ExploitNarrative,
		strings.Join(challenge.CounterArguments, " | "),
		strings.Join(challenge.RemainingQuestions, " | "),
		artifacts.FormatToolPath(pack.ObservedFlow), firstNonEmptyStr(strings.Join(pack.CounterEvidence, " | "), "(none)"),
		firstNonEmptyStr(caseCtx.tweText, "(none)"), renderArchitectureSlice(caseCtx.archModel), renderInvariants(caseCtx.invariants),
		renderToolFacts(caseCtx.toolFacts, caseCtx.missingToolFacts),
		formatSnippets(pack.Snippets),
		len(scFindings), formatCheckFindings(scFindings))

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		var parsed struct {
			Status                 string                `json:"status"`
			ChecksRun              []string              `json:"checks_run"`
			ConfirmedCitedFacts    []citations.CitedFact `json:"confirmed_cited_facts"`
			ContradictedCitedFacts []citations.CitedFact `json:"contradicted_cited_facts"`
			ConfirmedFacts         []string              `json:"confirmed_facts"`
			Contradictions         []string              `json:"contradictions"`
			Notes                  []string              `json:"notes"`
			Queries                []struct {
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
		resp, err := llm.GenerateJSON(ctx, client, "verifier", llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
			JSONMode:     true,
		}, &parsed)
		if err != nil {
			return artifacts.VerificationMemo{}, err
		}

		if len(parsed.Queries) == 0 {
			// Resolve verifier-produced citations against the repo.
			// Strict mode (V1.1.2 polish C1): a fact with any
			// citation failure ends up with empty Cited and is NOT
			// mirrored into the legacy ConfirmedFacts /
			// Contradictions arrays.
			confirmedCleaned, confirmedErrs := citations.ResolveFacts(parsed.ConfirmedCitedFacts, repoRoot)
			contradictedCleaned, contradictedErrs := citations.ResolveFacts(parsed.ContradictedCitedFacts, repoRoot)
			if n := len(confirmedErrs) + len(contradictedErrs); n > 0 {
				fmt.Printf("[verifier] %s: %d citation(s) failed to resolve\n", pack.CaseID, n)
			}
			confirmedText, confirmedPool := citations.FlattenFacts(confirmedCleaned)
			contradictedText, contradictedPool := citations.FlattenFacts(contradictedCleaned)

			// V1.1.2 polish C3: LLM legacy text-only fields land in
			// dedicated untyped channels. Mixing them into the
			// validated text fields would let unanchored claims
			// reach arbiter Evidence as if they were citation-backed
			// — same contract violation we just fixed on the expert
			// side (C2).
			pool := append(confirmedPool, contradictedPool...)
			return artifacts.VerificationMemo{
				SchemaVersion:          "teecheck.verification_memo.v1",
				CaseID:                 pack.CaseID,
				AgentID:                agentID,
				Status:                 normalizeVerifyStatus(parsed.Status),
				ChecksRun:              parsed.ChecksRun,
				ConfirmedFacts:         confirmedText,
				ConfirmedCitedFacts:    confirmedCleaned,
				UntypedConfirmedFacts:  parsed.ConfirmedFacts,
				Contradictions:         contradictedText,
				ContradictedCitedFacts: contradictedCleaned,
				UntypedContradictions:  parsed.Contradictions,
				Notes:                  parsed.Notes,
				Cited:                  pool,
			}, nil
		}

		var queryResults []string
		for i, q := range parsed.Queries {
			busResp, err := bus.AskForCase(ctx, pack.CaseID, agentbus.Query{
				QueryID:   fmt.Sprintf("verifier-%s-r%d-q%d", pack.CaseID, round, i),
				FromAgent: agentID,
				ToAgent:   q.ToAgent,
				Kind:      q.Kind,
				Question:  q.Question,
				Evidence:  busEvidence(pack, caseCtx),
			})
			if err != nil {
				queryResults = append(queryResults, fmt.Sprintf("Query to %s failed: %v", q.ToAgent, err))
				continue
			}
			queryResults = append(queryResults, fmt.Sprintf("Response from %s: %s\nFacts: %s", busResp.FromAgent, busResp.Answer, strings.Join(busResp.Facts, "; ")))
		}

		followUp := fmt.Sprintf("Here are the responses to your queries:\n%s\n\nNow provide your final judgment with the same JSON format.", strings.Join(queryResults, "\n\n"))
		messages = append(messages, llm.Message{Role: "assistant", Content: resp.Text})
		messages = append(messages, llm.Message{Role: "user", Content: followUp})
	}

	return artifacts.VerificationMemo{
		SchemaVersion: "teecheck.verification_memo.v1",
		CaseID:        pack.CaseID,
		AgentID:       agentID,
		Status:        "inconclusive",
		Notes:         []string{"Reached maximum dialog rounds without final judgment"},
	}, nil
}

// formatSnippets renders the case pack's code snippets into the
// verifier prompt. Each snippet is emitted as a fenced block with the
// path and line range so the LLM can cite `file:line` back at us.
// Caps each snippet at 20k characters (~5k tokens) and the total at
// 60k characters to keep the prompt under GLM's window while still
// giving the LLM enough to re-ground.
func formatSnippets(snippets []artifacts.PromptSnippet) string {
	if len(snippets) == 0 {
		return "(no snippets in case pack)"
	}
	const perSnippetCap = 20000
	const totalCap = 60000
	var b strings.Builder
	used := 0
	for i, s := range snippets {
		if used >= totalCap {
			fmt.Fprintf(&b, "\n(%d more snippets omitted — prompt cap reached)\n", len(snippets)-i)
			break
		}
		content := s.Content
		truncated := false
		if len(content) > perSnippetCap {
			content = content[:perSnippetCap]
			truncated = true
		}
		if used+len(content) > totalCap {
			content = content[:totalCap-used]
			truncated = true
		}
		fmt.Fprintf(&b, "\n--- %s [%d-%d] ---\n", s.Path, s.StartLine, s.EndLine)
		b.WriteString(content)
		if truncated {
			b.WriteString("\n... (truncated)\n")
		}
		b.WriteString("\n")
		used += len(content)
	}
	return b.String()
}

func formatCheckFindings(findings []staticcheck.CheckFinding) string {
	if len(findings) == 0 {
		return "  (none)"
	}
	var lines []string
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("  - [%s] %s:%d %s (severity: %s)", f.ToolName, f.Path, f.StartLine, f.Message, f.Severity))
	}
	return strings.Join(lines, "\n")
}

func normalizeVerifyStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "corroborated":
		return "corroborated"
	case "contested":
		return "contested"
	default:
		return "inconclusive"
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// formatUntypedFacts renders a hypothesis's UntypedFacts list with
// an explicit per-line [unanchored] tag so the verifier never
// confuses them with citation-anchored Supporting facts.
func formatUntypedFacts(untyped []string) string {
	if len(untyped) == 0 {
		return "(none)"
	}
	lines := make([]string, 0, len(untyped))
	for _, u := range untyped {
		lines = append(lines, "[unanchored] "+u)
	}
	return strings.Join(lines, " | ")
}

// emitVerifierClaimEvents fires one claim_emitted event per cited
// fact the verifier produced. Each fact gets a distinct claim_id so
// confirmed and contradicted claims do not collide. Unanchored
// facts (cited == []) still emit; downstream consumers decide what
// to do with citation-less claims.
func emitVerifierClaimEvents(rec events.Recorder, runID, agentID string, memo artifacts.VerificationMemo) {
	for i, f := range memo.ConfirmedCitedFacts {
		claimID := fmt.Sprintf("%s-confirmed-%03d", memo.CaseID, i+1)
		_ = rec.Emit(events.ClaimEmitted(runID, agentID, memo.CaseID, claimID, f.Text, f.Cited))
	}
	for i, f := range memo.ContradictedCitedFacts {
		claimID := fmt.Sprintf("%s-contradicted-%03d", memo.CaseID, i+1)
		_ = rec.Emit(events.ClaimEmitted(runID, agentID, memo.CaseID, claimID, f.Text, f.Cited))
	}
}

// formatExpertCitationStatus renders the per-fact validation list
// as the prompt block the verifier reads. One line per fact:
//
//	[<status>] <fact text> [optional: -- reason]
//
// followed by indented citation references when available, so the
// LLM can quote them verbatim if it decides to corroborate.
func formatExpertCitationStatus(validation []citations.CitationValidation) string {
	if len(validation) == 0 {
		return "(no expert facts produced)"
	}
	var b strings.Builder
	for i, v := range validation {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("- [%s] %s", v.Status, truncateStr(v.FactText, 200)))
		if v.Reason != "" {
			b.WriteString(fmt.Sprintf(" -- %s", truncateStr(v.Reason, 160)))
		}
		for _, c := range v.Cited {
			b.WriteString(fmt.Sprintf("\n    cite: %s:%d-%d", c.File, c.StartLine, c.EndLine))
		}
	}
	return b.String()
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
