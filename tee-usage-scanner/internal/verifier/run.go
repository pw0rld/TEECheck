package verifier

import (
	"fmt"
	"os"
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
		memo := buildMemo(manifest.LocalPath, pack, hypothesis, challenge, cfg.AgentID)
		target := filepath.Join(runfs.VerifierDir(cfg.RunDir), fmt.Sprintf("verify-%03d.json", idx+1))
		if err := runfs.WriteJSON(target, memo); err != nil {
			return fmt.Errorf("write verification memo %s: %w", memo.CaseID, err)
		}
		count++
	}
	fmt.Printf("Wrote %d verification memo(s) to %s\n", count, runfs.VerifierDir(cfg.RunDir))
	return nil
}

func buildMemo(repoRoot string, pack artifacts.CasePack, hypothesis artifacts.Hypothesis, challenge artifacts.Challenge, agentID string) artifacts.VerificationMemo {
	status := "inconclusive"
	checks := []string{"source scan for TODO/FIXME/unsafe markers", "cross-check open questions against file content"}
	var confirmed []string
	var contradictions []string

	for _, rel := range pack.TargetFiles {
		full := filepath.Join(repoRoot, rel)
		data, err := os.ReadFile(full)
		if err != nil {
			contradictions = append(contradictions, fmt.Sprintf("could not read %s", rel))
			continue
		}
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "todo") || strings.Contains(lower, "fixme") || strings.Contains(lower, "missing") {
			confirmed = append(confirmed, fmt.Sprintf("%s contains unfinished marker(s)", rel))
			status = "corroborated"
		}
		if strings.Contains(lower, "return err") || strings.Contains(lower, "return error") {
			confirmed = append(confirmed, fmt.Sprintf("%s contains explicit error-return path", rel))
		}
		if strings.Contains(lower, "bind") || strings.Contains(lower, "caller") || strings.Contains(lower, "authorize") {
			contradictions = append(contradictions, fmt.Sprintf("%s may already contain binding-related logic", rel))
			if status != "corroborated" {
				status = "contested"
			}
		}
	}

	if len(confirmed) == 0 && len(contradictions) == 0 {
		contradictions = append(contradictions, "No corroborating source markers were found in the current bounded files.")
	}

	notes := []string{
		"Verifier is intentionally lightweight in this phase and should be upgraded with targeted static tooling later.",
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
