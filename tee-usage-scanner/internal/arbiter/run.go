package arbiter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentbus"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/agentutil"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
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

		item, packet := arbitrate(pack, hypothesis, challenge, memo)
		if cfg.MaxFindings == 0 || len(findings.Findings) < cfg.MaxFindings {
			findings.Findings = append(findings.Findings, item)
		}
		packetPath := filepath.Join(runfs.ArbiterPacketsDir(cfg.RunDir), fmt.Sprintf("review-%03d.md", idx+1))
		if err := runfs.WriteText(packetPath, packet); err != nil {
			return fmt.Errorf("write arbiter packet: %w", err)
		}
		count++
	}
	if err := runfs.WriteJSON(runfs.ArbiterFindingsPath(cfg.RunDir), findings); err != nil {
		return fmt.Errorf("write arbiter findings: %w", err)
	}
	fmt.Printf("Wrote %d arbiter packet(s) to %s\n", count, runfs.ArbiterDir(cfg.RunDir))
	return nil
}

func arbitrate(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo) (artifacts.FindingItem, string) {
	status := "needs_review"
	confidence := "medium"
	severity := severityForCategory(pack.Category)
	switch memo.Status {
	case "corroborated":
		if hypothesis.Confidence == "high" {
			status = "confirmed_candidate"
			confidence = "high"
		} else {
			status = "likely_issue"
		}
	case "contested":
		status = "needs_review"
		confidence = "low"
	case "inconclusive":
		status = "needs_review"
		confidence = "low"
	}

	summary := fmt.Sprintf("%s | verifier=%s | exploitability=%s", hypothesis.SuspectedIssue, memo.Status, challenge.Exploitability)
	item := artifacts.FindingItem{
		FindingID:  pack.CaseID,
		SliceID:    pack.CaseID,
		Status:     status,
		Severity:   severity,
		Confidence: confidence,
		Files:      pack.TargetFiles,
		Summary:    summary,
		Evidence:   append(append([]string{}, hypothesis.SupportingFacts...), memo.ConfirmedFacts...),
	}

	packet := buildPacket(pack, hypothesis, challenge, memo, item)
	return item, packet
}

func buildPacket(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo, item artifacts.FindingItem) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Review Packet: %s\n\n", pack.CaseID))
	b.WriteString(fmt.Sprintf("- Category: `%s`\n", pack.Category))
	b.WriteString(fmt.Sprintf("- Priority: `%s`\n", pack.Priority))
	b.WriteString(fmt.Sprintf("- Arbiter Status: `%s`\n", item.Status))
	b.WriteString(fmt.Sprintf("- Confidence: `%s`\n\n", item.Confidence))
	b.WriteString("## Hypothesis\n\n")
	b.WriteString(fmt.Sprintf("- Title: %s\n", hypothesis.Title))
	b.WriteString(fmt.Sprintf("- Summary: %s\n", hypothesis.Summary))
	b.WriteString(fmt.Sprintf("- Missing obligations: %s\n\n", strings.Join(hypothesis.MissingObligations, ", ")))
	b.WriteString("## Challenger View\n\n")
	b.WriteString(fmt.Sprintf("- Exploitability: %s\n", challenge.Exploitability))
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
	b.WriteString("\n## Knowledge Hints\n\n")
	for _, hint := range pack.KnowledgeHints {
		b.WriteString(fmt.Sprintf("- %s: %s\n", hint.Title, hint.Reason))
	}
	b.WriteString("\n## Human Review Prompt\n\n")
	b.WriteString("- Does the visible code really represent the trust decision point?\n")
	b.WriteString("- Is wrapper or helper context likely to change this verdict?\n")
	b.WriteString("- If the issue is real, what concrete security property fails?\n")
	return b.String()
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

func RunWithBus(cfg config.Config, bus *agentbus.Bus) error {
	casePaths, err := filepath.Glob(filepath.Join(runfs.CasePacksDir(cfg.RunDir), "case-*.json"))
	if err != nil {
		return fmt.Errorf("glob case packs: %w", err)
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	client := llm.NewClient(cfg)

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

		bus.ResetDialog(pack.CaseID)
		item, packet, err := arbitrateLLM(context.Background(), client, bus, pack, hypothesis, challenge, memo, cfg.AgentID, cfg.LLMTemp)
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

func arbitrateLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, memo artifacts.VerificationMemo, agentID string, temperature float64) (artifacts.FindingItem, string, error) {
	systemPrompt := `You are the Arbiter Agent in TEECheck. Synthesize all evidence and produce a final judgment and human-readable review packet.

Return a JSON object with fields:
- status: "no_issue_observed" | "needs_review" | "likely_issue" | "confirmed_candidate"
- severity: "high" | "medium" | "low"
- confidence: "high" | "medium" | "low"
- summary: string
- evidence: array of strings
- review_packet_markdown: string (full review packet in markdown)
- queries: array of objects (optional, each with: to_agent, kind, question)`

	userMsg := fmt.Sprintf(`Case: %s (category: %s, priority: %s)
Files: %s

Expert hypothesis:
- Title: %s
- Suspected issue: %s
- Confidence: %s
- Supporting facts: %s

Challenger view:
- Exploitability: %s
- Stance: %s
- Counter arguments: %s

Verification:
- Status: %s
- Confirmed facts: %s
- Contradictions: %s

Knowledge hints:
%s`,
		pack.CaseID, pack.Category, pack.Priority,
		strings.Join(pack.TargetFiles, ", "),
		hypothesis.Title, hypothesis.SuspectedIssue, hypothesis.Confidence,
		strings.Join(hypothesis.SupportingFacts, " | "),
		challenge.Exploitability, challenge.ReviewerStance,
		strings.Join(challenge.CounterArguments, " | "),
		memo.Status,
		strings.Join(memo.ConfirmedFacts, " | "),
		strings.Join(memo.Contradictions, " | "),
		formatKnowledgeHintsForLLM(pack.KnowledgeHints))

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
		})
		if err != nil {
			return artifacts.FindingItem{}, "", fmt.Errorf("llm generate: %w", err)
		}

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
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return artifacts.FindingItem{}, "", fmt.Errorf("parse arbiter json: %w | raw=%s", err, truncateArbiter(resp.Text, 400))
		}

		if len(parsed.Queries) == 0 {
			item := artifacts.FindingItem{
				FindingID:  pack.CaseID,
				SliceID:    pack.CaseID,
				Status:     parsed.Status,
				Severity:   parsed.Severity,
				Confidence: parsed.Confidence,
				Files:      pack.TargetFiles,
				Summary:    parsed.Summary,
				Evidence:   parsed.Evidence,
			}
			packet := parsed.ReviewPacketMarkdown
			if packet == "" {
				packet = buildPacket(pack, hypothesis, challenge, memo, item)
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

	item := artifacts.FindingItem{
		FindingID:  pack.CaseID,
		SliceID:    pack.CaseID,
		Status:     "needs_review",
		Severity:   severityForCategory(pack.Category),
		Confidence: "low",
		Files:      pack.TargetFiles,
		Summary:    "Reached maximum dialog rounds without final arbiter judgment",
	}
	return item, buildPacket(pack, hypothesis, challenge, memo, item), nil
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

func truncateArbiter(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
