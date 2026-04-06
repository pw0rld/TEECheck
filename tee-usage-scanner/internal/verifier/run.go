package verifier

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
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
