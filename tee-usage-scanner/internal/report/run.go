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

type reviewPacket struct {
	Name    string
	Content string
}

// Run writes an authoritative factual report from structured artifacts. The
// optional model contributes only a labeled narrative; it cannot add, remove,
// reorder, or truncate findings and review packets.
func Run(cfg config.Config, client llm.Client) error {
	if cfg.RunDir == "" {
		return fmt.Errorf("--run-dir is required")
	}
	manifest, err := runfs.LoadManifest(cfg.RunDir)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	var findings artifacts.Findings
	if err := runfs.ReadJSON(runfs.ArbiterFindingsPath(cfg.RunDir), &findings); err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	if err := findings.Validate(); err != nil {
		return fmt.Errorf("validate findings: %w", err)
	}
	if findings.RunID != manifest.RunID {
		return fmt.Errorf("findings run_id %q does not match manifest run_id %q", findings.RunID, manifest.RunID)
	}

	packets, err := loadReviewPackets(cfg.RunDir)
	if err != nil {
		return err
	}
	var bundle artifacts.EvidenceBundle
	hasPlannerMeta := runfs.ReadJSON(runfs.EvidenceBundlePath(cfg.RunDir), &bundle) == nil
	var coverage artifacts.CoverageLedger
	hasCoverage := runfs.ReadJSON(runfs.CoverageLedgerPath(cfg.RunDir), &coverage) == nil

	narrative, narrativeErr := generateNarrative(client, manifest, findings, bundle, hasPlannerMeta)
	if narrativeErr != nil || strings.TrimSpace(narrative) == "" {
		narrative = fmt.Sprintf(
			"Narrative unavailable. The authoritative sections below record %d finding(s) from the validated findings artifact.",
			len(findings.Findings))
	}
	reportContent := buildReport(manifest, findings, packets, bundle, hasPlannerMeta, coverage, hasCoverage, narrative)

	reportDir := filepath.Join(cfg.RunDir, "08_report")
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

func loadReviewPackets(runDir string) ([]reviewPacket, error) {
	paths, err := filepath.Glob(filepath.Join(runfs.ArbiterPacketsDir(runDir), "review-*.md"))
	if err != nil {
		return nil, fmt.Errorf("list review packets: %w", err)
	}
	sort.Strings(paths)
	packets := make([]reviewPacket, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read review packet %s: %w", path, err)
		}
		packets = append(packets, reviewPacket{Name: filepath.Base(path), Content: string(data)})
	}
	return packets, nil
}

func generateNarrative(client llm.Client, manifest artifacts.Manifest, findings artifacts.Findings, bundle artifacts.EvidenceBundle, hasPlannerMeta bool) (string, error) {
	if client == nil {
		return "", fmt.Errorf("no narrative client")
	}
	var input strings.Builder
	fmt.Fprintf(&input, "Run %s audited %s at %s with focus %s.\n", manifest.RunID, manifest.RepoURL, manifest.Commit, manifest.Focus)
	fmt.Fprintf(&input, "Validated findings count: %d.\n", len(findings.Findings))
	for _, finding := range sortedFindings(findings.Findings) {
		fmt.Fprintf(&input, "- %s: status=%s severity=%s confidence=%s summary=%s\n",
			finding.FindingID, finding.Status, finding.Severity, finding.Confidence,
			truncateText(finding.Summary, 500))
	}
	if hasPlannerMeta {
		fmt.Fprintf(&input, "Planner: candidates=%d rounds=%d/%d tokens=%d termination=%s.\n",
			len(bundle.Candidates), bundle.PlannerMeta.RoundsUsed, bundle.PlannerMeta.RoundsBudget,
			bundle.PlannerMeta.TokensUsed, bundle.PlannerMeta.TerminationReason)
	}

	resp, err := client.Generate(context.Background(), llm.GenerateRequest{
		SystemPrompt: `Write two short paragraphs for the non-authoritative narrative section of a TEECheck report. Summarize only the supplied facts and suggest human review priorities. Do not restate detailed evidence, invent claims, or omit caveats. The structured report is authoritative.`,
		Messages:     []llm.Message{{Role: "user", Content: input.String()}},
		Temperature:  0.1,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Text), nil
}

func buildReport(manifest artifacts.Manifest, findings artifacts.Findings, packets []reviewPacket, bundle artifacts.EvidenceBundle, hasPlannerMeta bool, coverage artifacts.CoverageLedger, hasCoverage bool, narrative string) string {
	ordered := sortedFindings(findings.Findings)
	var b strings.Builder
	b.WriteString("# TEECheck Audit Report\n\n")
	b.WriteString("> Structured artifacts are authoritative. The narrative is model-generated and non-authoritative.\n\n")
	b.WriteString("## Run\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Run ID | `%s` |\n| Repository | `%s` |\n| Commit | `%s` |\n| Focus | `%s` |\n| Findings | %d |\n",
		manifest.RunID, manifest.RepoURL, manifest.Commit, manifest.Focus, len(ordered))
	if manifest.Build != nil {
		fmt.Fprintf(&b, "| TEECheck build | `%s` |\n| Go version | `%s` |\n| Scanner revision | `%s` |\n| Scanner tree modified | %t |\n",
			manifest.Build.Version, manifest.Build.GoVersion, manifest.Build.VCSRevision, manifest.Build.VCSModified)
	}
	if manifest.Configuration != nil {
		llmConfig := manifest.Configuration.LLM
		fmt.Fprintf(&b, "| LLM provider | `%s` |\n| LLM model | `%s` |\n| LLM transport | `%s` |\n| Reasoning effort | `%s` |\n| Per-call output tokens | %d |\n",
			llmConfig.Provider, llmConfig.Model, llmConfig.Transport, llmConfig.ReasoningEffort, llmConfig.MaxOutputTokens)
	}
	b.WriteString("\n")

	b.WriteString("## Narrative\n\n")
	b.WriteString(narrative)
	b.WriteString("\n\n")

	b.WriteString("## Findings Index\n\n")
	if len(ordered) == 0 {
		b.WriteString("No findings were emitted. This is not proof that no issue exists; consult planner coverage and run integrity.\n\n")
	} else {
		b.WriteString("| Finding | Status | Severity | Confidence | Summary |\n|---|---|---|---|---|\n")
		for _, finding := range ordered {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				finding.FindingID, finding.Status, finding.Severity, finding.Confidence, tableText(finding.Summary))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Finding Details\n\n")
	for _, finding := range ordered {
		renderFinding(&b, finding)
	}

	b.WriteString("## Planner And Coverage\n\n")
	if !hasPlannerMeta {
		b.WriteString("Planner metadata is unavailable.\n\n")
	} else {
		fmt.Fprintf(&b, "| Metric | Value |\n|---|---:|\n| Candidates | %d |\n| Rounds | %d / %d |\n| Tokens | %d |\n| Wall clock (ms) | %d |\n| Termination | `%s` |\n\n",
			len(bundle.Candidates), bundle.PlannerMeta.RoundsUsed, bundle.PlannerMeta.RoundsBudget,
			bundle.PlannerMeta.TokensUsed, bundle.PlannerMeta.WallClockMs, bundle.PlannerMeta.TerminationReason)
		if len(bundle.Candidates) > 0 {
			b.WriteString("### Candidates\n\n")
			for _, candidate := range bundle.Candidates {
				fmt.Fprintf(&b, "- `%s` (%s, %s): %s\n", candidate.ID, candidate.Kind, candidate.Priority, strings.Join(candidate.Paths, ", "))
			}
			b.WriteString("\n")
		}
	}
	if hasCoverage {
		b.WriteString("### Coverage Ledger\n\n")
		fmt.Fprintf(&b, "| Metric | Reviewed | Total |\n|---|---:|---:|\n| Modules reviewed | %d | %d |\n| Function capsules reviewed | %d | %d |\n| Leads open | %d |  |\n\n",
			coverage.ModulesReviewed, coverage.ModulesTotal,
			coverage.FunctionCapsulesReviewed, coverage.FunctionCapsulesTotal,
			coverage.LeadsOpen)
		if len(coverage.BySample) > 0 {
			b.WriteString("#### Per-Sample Coverage\n\n")
			b.WriteString("| Sample | Recon mode | Recon status | Modules | Capsules | Files | Relation queries | Rounds | Recon rounds | Leads |\n|---:|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
			for _, sample := range coverage.BySample {
				fmt.Fprintf(&b, "| %d | %s | %s | %d | %d | %d | %d | %d | %d | %d |\n",
					sample.SampleIndex, sample.ReconMode, sample.ReconStatus,
					len(sample.ModulesReviewed), sample.CapsulesReviewed, sample.FilesRead,
					sample.RelationQueriesRun, sample.RoundsUsed, sample.ReconRoundsUsed, sample.LeadsOpened)
			}
			b.WriteString("\n")
			b.WriteString("#### Entry Source Coverage\n\n| Sample | Capability | Entry windows read | Required | Modules read | Required modules | Zero-lead gate |\n|---:|---|---:|---:|---:|---:|---|\n")
			for _, sample := range coverage.BySample {
				if entry := sample.EntrySurfaces; entry != nil {
					fmt.Fprintf(&b, "| %d | %s | %d | %d | %d | %d | %t |\n", sample.SampleIndex, entry.Capability, entry.Read, entry.Required, entry.ModulesRead, entry.ModulesRequired, entry.GateApplies)
				}
			}
			b.WriteString("\nThese are opening source windows, not whole-function or whole-repository safety conclusions.\n\n")
		}
		renderList(&b, "Unreviewed Clusters", coverage.UnreviewedClusters)
	}

	b.WriteString("## Review Packets\n\n")
	if len(packets) == 0 {
		b.WriteString("No review packets were present.\n")
	}
	for _, packet := range packets {
		fmt.Fprintf(&b, "### `%s`\n\n", packet.Name)
		b.WriteString(packet.Content)
		if !strings.HasSuffix(packet.Content, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderFinding(b *strings.Builder, finding artifacts.FindingItem) {
	fmt.Fprintf(b, "### `%s`: %s\n\n", finding.FindingID, finding.Summary)
	fmt.Fprintf(b, "| Field | Value |\n|---|---|\n| Slice | `%s` |\n| Status | %s |\n| Severity | %s |\n| Confidence | %s |\n",
		finding.SliceID, finding.Status, finding.Severity, finding.Confidence)
	fmt.Fprintf(b, "| Files | %s |\n| Locations | %s |\n\n",
		tableText(strings.Join(finding.Files, ", ")), tableText(formatLocations(finding.Locations)))
	renderList(b, "Evidence", finding.Evidence)
	if finding.Sections == nil {
		return
	}
	sections := finding.Sections
	renderList(b, "Anchored Tool Facts", sections.AnchoredToolFacts)
	renderList(b, "Architecture Evidence Status", sections.ArchitectureEvidenceStatus)
	renderList(b, "Invariant Verification Status", sections.InvariantVerificationStatus)
	renderText(b, "Expert Hypothesis", sections.ExpertHypothesis)
	renderText(b, "Independent Challenger Result", sections.IndependentChallengerResult)
	renderText(b, "Verifier Resolution", sections.VerifierResolution)
	renderList(b, "Remaining Coverage Gaps", sections.RemainingCoverageGaps)
	renderList(b, "Human Review Questions", sections.HumanReviewQuestions)
}

func renderList(b *strings.Builder, title string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n", title)
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", value)
	}
	b.WriteString("\n")
}

func renderText(b *strings.Builder, title, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n%s\n\n", title, value)
}

func sortedFindings(findings []artifacts.FindingItem) []artifacts.FindingItem {
	ordered := append([]artifacts.FindingItem(nil), findings...)
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	sort.SliceStable(ordered, func(i, j int) bool {
		if rank[ordered[i].Severity] != rank[ordered[j].Severity] {
			return rank[ordered[i].Severity] > rank[ordered[j].Severity]
		}
		if rank[ordered[i].Confidence] != rank[ordered[j].Confidence] {
			return rank[ordered[i].Confidence] > rank[ordered[j].Confidence]
		}
		return ordered[i].FindingID < ordered[j].FindingID
	})
	return ordered
}

func formatLocations(locations []artifacts.FindingLocation) string {
	values := make([]string, 0, len(locations))
	for _, location := range locations {
		values = append(values, fmt.Sprintf("%s:%d", location.Path, location.StartLine))
	}
	return strings.Join(values, ", ")
}

func tableText(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func truncateText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
