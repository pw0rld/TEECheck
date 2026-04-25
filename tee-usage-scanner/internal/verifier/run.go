package verifier

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
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck"
	scall "github.com/pw0rld/TEECheck/tee-usage-scanner/internal/staticcheck/all"
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

		// Run static checks
		var scFindings []staticcheck.CheckFinding
		if enabledTools != nil {
			req := staticcheck.CheckRequest{
				RepoRoot:    manifest.LocalPath,
				TargetFiles: pack.TargetFiles,
				Keywords:    append(pack.ExpectedObligations, pack.TargetSymbols...),
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

		memo := buildMemo(pack, hypothesis, challenge, cfg.AgentID, scFindings)
		target := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, memo); err != nil {
			return fmt.Errorf("write verification memo %s: %w", memo.CaseID, err)
		}
		count++
	}
	fmt.Printf("Wrote %d verification memo(s) to %s\n", count, runfs.VerifierDir(cfg.RunDir))
	return nil
}

func buildMemo(pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, agentID string, scFindings []staticcheck.CheckFinding) artifacts.VerificationMemo {
	status := "inconclusive"
	var checks []string
	var confirmed []string
	var contradictions []string

	for _, f := range scFindings {
		checks = append(checks, fmt.Sprintf("%s: %s", f.ToolName, f.RuleID))
		lower := strings.ToLower(f.Message)
		if strings.Contains(lower, "todo") || strings.Contains(lower, "fixme") || strings.Contains(lower, "missing") {
			confirmed = append(confirmed, fmt.Sprintf("%s:%d %s (via %s)", f.Path, f.StartLine, f.Message, f.ToolName))
			status = "corroborated"
		} else if strings.Contains(lower, "bind") || strings.Contains(lower, "caller") || strings.Contains(lower, "authorize") {
			contradictions = append(contradictions, fmt.Sprintf("%s:%d may contain binding logic (via %s)", f.Path, f.StartLine, f.ToolName))
			if status != "corroborated" {
				status = "contested"
			}
		} else if f.Severity == "warning" || f.Severity == "error" {
			confirmed = append(confirmed, fmt.Sprintf("%s:%d %s (via %s)", f.Path, f.StartLine, f.Message, f.ToolName))
			status = "corroborated"
		}
	}

	if len(checks) == 0 {
		checks = append(checks, "no static checks ran")
	}
	if len(confirmed) == 0 && len(contradictions) == 0 {
		contradictions = append(contradictions, "No corroborating evidence found in the bounded files.")
	}

	notes := []string{
		fmt.Sprintf("Static tools used: %s", strings.Join(toolNames(scFindings), ", ")),
	}
	if hypothesis.NeedsVerification {
		notes = append(notes, "Expert explicitly requested follow-up verification.")
	}
	if len(challenge.RemainingQuestions) > 0 {
		notes = append(notes, "Challenger left unresolved questions that may require wrapper-context inspection.")
	}

	return artifacts.VerificationMemo{
		SchemaVersion:  "teecheck.verification_memo.v1",
		CaseID:         pack.CaseID,
		AgentID:        agentID,
		Status:         status,
		ChecksRun:      checks,
		ConfirmedFacts: confirmed,
		Contradictions: contradictions,
		Notes:          notes,
	}
}

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

func toolNames(findings []staticcheck.CheckFinding) []string {
	seen := map[string]bool{}
	var names []string
	for _, f := range findings {
		if !seen[f.ToolName] {
			seen[f.ToolName] = true
			names = append(names, f.ToolName)
		}
	}
	if len(names) == 0 {
		return []string{"none"}
	}
	return names
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

		var scFindings []staticcheck.CheckFinding
		if enabledTools != nil {
			req := staticcheck.CheckRequest{
				RepoRoot:    manifest.LocalPath,
				TargetFiles: pack.TargetFiles,
				Keywords:    append(pack.ExpectedObligations, pack.TargetSymbols...),
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

		bus.ResetDialog(pack.CaseID)
		memo, err := buildMemoLLM(context.Background(), client, bus, pack, hypothesis, challenge, cfg.AgentID, cfg.LLMTemp, scFindings)
		if err != nil {
			return fmt.Errorf("verifier llm for %s: %w", pack.CaseID, err)
		}

		target := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, memo); err != nil {
			return fmt.Errorf("write verification memo: %w", err)
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

func buildMemoLLM(ctx context.Context, client llm.Client, bus *agentbus.Bus, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, agentID string, temperature float64, scFindings []staticcheck.CheckFinding) (artifacts.VerificationMemo, error) {
	systemPrompt := `You are the Verifier Agent in TEECheck. Analyze static check results and code evidence to arbitrate between the Expert's hypothesis and the Challenger's objections.

Return a JSON object with fields:
- status: "corroborated" | "contested" | "inconclusive"
- checks_run: array of strings
- confirmed_facts: array of strings
- contradictions: array of strings
- notes: array of strings
- queries: array of objects (optional, each with: to_agent, kind, question)`

	userMsg := fmt.Sprintf(`Case: %s (category: %s, priority: %s)
Target files: %s
Target symbols: %s

Expert hypothesis:
- Title: %s
- Suspected issue: %s
- Missing obligations: %s
- Supporting facts: %s
- Confidence: %s

Challenger view:
- Exploitability: %s
- Narrative: %s
- Counter arguments: %s
- Remaining questions: %s

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
		hypothesis.Confidence,
		challenge.Exploitability, challenge.ExploitNarrative,
		strings.Join(challenge.CounterArguments, " | "),
		strings.Join(challenge.RemainingQuestions, " | "),
		formatSnippets(pack.Snippets),
		len(scFindings), formatCheckFindings(scFindings))

	messages := []llm.Message{{Role: "user", Content: userMsg}}

	for round := 0; round < bus.MaxRounds()+1; round++ {
		resp, err := client.Generate(ctx, llm.GenerateRequest{
			SystemPrompt: systemPrompt,
			Messages:     messages,
			Temperature:  temperature,
			JSONMode:     true,
		})
		if err != nil {
			return artifacts.VerificationMemo{}, fmt.Errorf("llm generate: %w", err)
		}

		var parsed struct {
			Status         string   `json:"status"`
			ChecksRun      []string `json:"checks_run"`
			ConfirmedFacts []string `json:"confirmed_facts"`
			Contradictions []string `json:"contradictions"`
			Notes          []string `json:"notes"`
			Queries        []struct {
				ToAgent  string `json:"to_agent"`
				Kind     string `json:"kind"`
				Question string `json:"question"`
			} `json:"queries"`
		}
		if err := agentutil.UnmarshalJSONObject(resp.Text, &parsed); err != nil {
			return artifacts.VerificationMemo{}, fmt.Errorf("parse verifier json: %w | raw=%s", err, truncateStr(resp.Text, 400))
		}

		if len(parsed.Queries) == 0 {
			return artifacts.VerificationMemo{
				SchemaVersion:  "teecheck.verification_memo.v1",
				CaseID:         pack.CaseID,
				AgentID:        agentID,
				Status:         normalizeVerifyStatus(parsed.Status),
				ChecksRun:      parsed.ChecksRun,
				ConfirmedFacts: parsed.ConfirmedFacts,
				Contradictions: parsed.Contradictions,
				Notes:          parsed.Notes,
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
