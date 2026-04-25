package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/runfs"
)

// Run generates a unified audit report from a completed TEECheck run.
// In LLM mode, an LLM synthesizes a cross-finding executive summary,
// coverage analysis, and per-finding sections from the raw review
// packets. In heuristic mode, packets are concatenated with headers.
//
// Output: <runDir>/08_report/REPORT.md
func Run(cfg config.Config) error {
	runDir := cfg.RunDir
	if runDir == "" {
		return fmt.Errorf("--run-dir is required")
	}

	manifest, err := runfs.LoadManifest(runDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(runDir), &findings); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	// Load all review packets
	packetPaths, _ := filepath.Glob(filepath.Join(runfs.ArbiterPacketsDir(runDir), "review-*.md"))
	sort.Strings(packetPaths)
	var packets []string
	for _, p := range packetPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		packets = append(packets, string(data))
	}

	// Load planner metadata if available
	var bundle artifacts.EvidenceBundle
	hasPlannerMeta := false
	if err := runfs.ReadJSON(runfs.EvidenceBundlePath(runDir), &bundle); err == nil {
		hasPlannerMeta = true
	}

	var reportContent string
	if strings.EqualFold(cfg.Mode, "llm") || strings.EqualFold(cfg.VerifierMode, "llm") {
		reportContent, err = generateLLMReport(cfg, manifest, findings, packets, bundle, hasPlannerMeta)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: LLM report generation failed (%v), falling back to heuristic\n", err)
			reportContent = generateHeuristicReport(manifest, findings, packets, bundle, hasPlannerMeta)
		}
	} else {
		reportContent = generateHeuristicReport(manifest, findings, packets, bundle, hasPlannerMeta)
	}

	reportDir := filepath.Join(runDir, "08_report")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}
	reportPath := filepath.Join(reportDir, "REPORT.md")
	if err := os.WriteFile(reportPath, []byte(reportContent), 0o644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	fmt.Printf("Report written to %s (%d findings)\n", reportPath, len(findings.Findings))
	return nil
}

func generateLLMReport(cfg config.Config, manifest artifacts.Manifest, findings artifacts.Findings, packets []string, bundle artifacts.EvidenceBundle, hasPlannerMeta bool) (string, error) {
	client := llm.NewClient(cfg)

	systemPrompt := `You are a senior TEE security auditor writing the final unified report for a TEECheck audit run. You receive:
1. A findings summary (JSON) with status, severity, confidence for each finding
2. The full review packets (markdown) for every finding — each contains Expert hypothesis, Challenger objections, Verifier evidence, and Arbiter judgment
3. Optional planner metadata (candidates, coverage, tokens)

Your job: produce a single, comprehensive markdown audit report that:
- Starts with an executive summary (2-3 paragraphs: what was audited, key results, recommended actions)
- Lists EVERY finding with its full analysis — do NOT omit or minimize any finding regardless of confidence level
- For each finding include: status, severity, confidence, file(s), the core observation, evidence, and recommended human follow-up
- Orders findings by severity desc then confidence desc, but includes ALL of them
- Ends with a coverage section (what directories/crates were audited, what was missed)
- Ends with concrete next steps for the human reviewer

Rules:
- Include ALL findings. The human reviewer decides what to prioritize, not you.
- Use the exact evidence and citations from the review packets — do not invent new claims.
- Mark each finding with its verifier status (corroborated / contested / inconclusive) prominently.
- Write in English. Use markdown formatting. Be direct and specific.`

	var userMsgParts []string

	// Findings summary
	userMsgParts = append(userMsgParts, "## Findings Summary (JSON)\n")
	findingsLines := []string{}
	for _, f := range findings.Findings {
		findingsLines = append(findingsLines, fmt.Sprintf("- %s | status=%s | severity=%s | confidence=%s | files=%v",
			f.FindingID, f.Status, f.Severity, f.Confidence, f.Files))
	}
	userMsgParts = append(userMsgParts, strings.Join(findingsLines, "\n"))

	// Planner metadata
	if hasPlannerMeta {
		userMsgParts = append(userMsgParts, fmt.Sprintf("\n\n## Planner Metadata\n- Candidates: %d\n- Rounds: %d\n- Tokens: %d\n- Wall clock: %dms\n- Termination: %s",
			len(bundle.Candidates), bundle.PlannerMeta.RoundsUsed, bundle.PlannerMeta.TokensUsed,
			bundle.PlannerMeta.WallClockMs, bundle.PlannerMeta.TerminationReason))

		var candLines []string
		for _, c := range bundle.Candidates {
			candLines = append(candLines, fmt.Sprintf("  - %s [%s, %s] paths=%v", c.ID, c.Kind, c.Priority, c.Paths))
		}
		userMsgParts = append(userMsgParts, "\n- Candidate list:\n"+strings.Join(candLines, "\n"))
	}

	userMsgParts = append(userMsgParts, fmt.Sprintf("\n\n## Run Info\n- Repo: %s\n- Commit: %s\n- Run ID: %s",
		manifest.RepoURL, manifest.Commit, manifest.RunID))

	// All review packets
	userMsgParts = append(userMsgParts, "\n\n## Full Review Packets\n")
	for i, pkt := range packets {
		// Cap each packet to avoid blowing context
		content := pkt
		if len(content) > 8000 {
			content = content[:8000] + "\n... (truncated)"
		}
		userMsgParts = append(userMsgParts, fmt.Sprintf("\n### Packet %d/%d\n%s", i+1, len(packets), content))
	}

	userMsg := strings.Join(userMsgParts, "")

	// Cap total input
	if len(userMsg) > 120000 {
		userMsg = userMsg[:120000] + "\n\n... (remaining packets truncated to fit context window)"
	}

	resp, err := client.Generate(context.Background(), llm.GenerateRequest{
		SystemPrompt: systemPrompt,
		Messages:     []llm.Message{{Role: "user", Content: userMsg}},
		Temperature:  0.1, // Low temperature for factual report
	})
	if err != nil {
		return "", fmt.Errorf("llm generate: %w", err)
	}

	return resp.Text, nil
}

func generateHeuristicReport(manifest artifacts.Manifest, findings artifacts.Findings, packets []string, bundle artifacts.EvidenceBundle, hasPlannerMeta bool) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# TEECheck Audit Report — %s\n\n", manifest.RunID))
	b.WriteString(fmt.Sprintf("**Repo:** %s\n", manifest.RepoURL))
	b.WriteString(fmt.Sprintf("**Commit:** %s\n", manifest.Commit))
	b.WriteString(fmt.Sprintf("**Findings:** %d\n\n", len(findings.Findings)))

	if hasPlannerMeta {
		m := bundle.PlannerMeta
		b.WriteString(fmt.Sprintf("**Planner:** %d candidates, %d rounds, %d tokens, termination=%s\n\n",
			len(bundle.Candidates), m.RoundsUsed, m.TokensUsed, m.TerminationReason))
	}

	b.WriteString("## Findings Summary\n\n")
	b.WriteString("| # | Status | Severity | Confidence | Files |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for i, f := range findings.Findings {
		files := strings.Join(f.Files, ", ")
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n", i+1, f.Status, f.Severity, f.Confidence, files))
	}
	b.WriteString("\n---\n\n")

	// Append all review packets verbatim
	for i, pkt := range packets {
		b.WriteString(fmt.Sprintf("## Finding %d/%d\n\n", i+1, len(packets)))
		b.WriteString(pkt)
		b.WriteString("\n\n---\n\n")
	}

	return b.String()
}
