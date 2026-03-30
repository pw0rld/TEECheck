package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/config"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/evidence"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/joern"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/llm"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/report"
	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/rules"
)

func Run(cfg config.Config) error {
	ruleSet, err := rules.LoadDir(cfg.RuleDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	packages, err := loadEvidence(cfg)
	if err != nil {
		return err
	}

	var findings []report.Finding
	for _, ev := range packages {
		for _, rule := range ruleSet {
			finding, ok := rules.Evaluate(rule, ev)
			if !ok {
				continue
			}
			findings = append(findings, finding)
			if finding.NeedsReview {
				if err := llm.WriteReviewBundle(cfg.ReviewDir, rule, ev, finding); err != nil {
					return fmt.Errorf("write review bundle: %w", err)
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})

	rep := report.Report{
		SchemaVersion: "teecheck.demo.report.v1",
		RuleCount:     len(ruleSet),
		EvidenceCount: len(packages),
		FindingCount:  len(findings),
		Findings:      findings,
	}

	if err := os.MkdirAll(filepath.Dir(cfg.ReportPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.ReportPath, data, 0o644); err != nil {
		return err
	}

	fmt.Printf("Loaded %d rule(s), %d evidence package(s), emitted %d finding(s).\n", rep.RuleCount, rep.EvidenceCount, rep.FindingCount)
	fmt.Printf("Report: %s\n", cfg.ReportPath)
	if strings.TrimSpace(cfg.ReviewDir) != "" {
		fmt.Printf("Review bundles: %s\n", cfg.ReviewDir)
	}
	return nil
}

func loadEvidence(cfg config.Config) ([]evidence.Package, error) {
	if cfg.SourcePath != "" {
		client := joern.Client{
			Binary:     cfg.JoernBin,
			Endpoint:   cfg.JoernEndpoint,
			SSHTarget:  cfg.JoernSSHTarget,
			RemoteRoot: cfg.JoernWorkspace,
		}
		return client.ExportEvidence(cfg.SourcePath)
	}

	if strings.TrimSpace(cfg.FixtureDir) == "" {
		return nil, fmt.Errorf("fixture dir is empty; provide --fixture-dir or use --src with a live Joern backend")
	}

	entries, err := os.ReadDir(cfg.FixtureDir)
	if err != nil {
		return nil, fmt.Errorf("read evidence fixture dir: %w", err)
	}

	var packages []evidence.Package
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(cfg.FixtureDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var pack evidence.Package
		if err := json.Unmarshal(data, &pack); err != nil {
			return nil, fmt.Errorf("parse evidence fixture %s: %w", path, err)
		}
		packages = append(packages, pack)
	}

	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Candidate.ID < packages[j].Candidate.ID
	})
	return packages, nil
}
