package arbiter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
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
