package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type loadedCase struct {
	Dir    string
	Case   caseSpec
	Oracle oracleSpec
}

type teecheckFindings struct {
	SchemaVersion string            `json:"schema_version"`
	RunID         string            `json:"run_id"`
	Findings      []teecheckFinding `json:"findings"`
}

type teecheckFinding struct {
	FindingID string   `json:"finding_id"`
	Status    string   `json:"status"`
	Files     []string `json:"files"`
	Summary   string   `json:"summary"`
	Evidence  []string `json:"evidence"`
}

type variantScore struct {
	Variant        string   `json:"variant"`
	Expected       string   `json:"expected"`
	Observed       string   `json:"observed"`
	Classification string   `json:"classification"`
	MatchedFinding string   `json:"matched_finding,omitempty"`
	MatchReasons   []string `json:"match_reasons,omitempty"`
	FindingsPath   string   `json:"findings_path"`
	FindingCount   int      `json:"finding_count"`
}

type caseScore struct {
	CaseID     string       `json:"case_id"`
	PairedPass bool         `json:"paired_pass"`
	Vulnerable variantScore `json:"vulnerable"`
	Fixed      variantScore `json:"fixed"`
}

type scoreReport struct {
	Schema       string      `json:"schema"`
	GeneratedAt  string      `json:"generated_at"`
	Cases        []caseScore `json:"cases"`
	Totals       scoreTotals `json:"totals"`
	Precision    float64     `json:"precision"`
	Recall       float64     `json:"recall"`
	F1           float64     `json:"f1"`
	Specificity  float64     `json:"specificity"`
	PairedPasses int         `json:"paired_passes"`
	PairedRate   float64     `json:"paired_pass_rate"`
}

type scoreTotals struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`
}

func loadCase(dir string) (loadedCase, error) {
	var c caseSpec
	if err := readJSON(filepath.Join(dir, "case.yaml"), &c); err != nil {
		return loadedCase{}, err
	}
	var o oracleSpec
	if err := readJSON(filepath.Join(dir, "oracle.yaml"), &o); err != nil {
		return loadedCase{}, err
	}
	return loadedCase{Dir: dir, Case: c, Oracle: o}, nil
}

func evaluate(cases []loadedCase, resultsDir, commandTemplate string, timeout time.Duration) error {
	for _, c := range cases {
		for _, variant := range []string{"vulnerable", "fixed"} {
			input, err := filepath.Abs(filepath.Join(c.Dir, variant))
			if err != nil {
				return err
			}
			runDir, err := filepath.Abs(filepath.Join(resultsDir, c.Case.ID, variant))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				return err
			}
			command := expandCommand(commandTemplate, map[string]string{
				"input": input, "run_dir": runDir, "case": c.Case.ID, "variant": variant,
			})
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			cmd := exec.CommandContext(ctx, "sh", "-c", command)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			fmt.Printf("RUN %s/%s\n", c.Case.ID, variant)
			err = cmd.Run()
			cancel()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%s/%s scanner timeout after %s", c.Case.ID, variant, timeout)
			}
			if err != nil {
				return fmt.Errorf("%s/%s scanner failed: %w", c.Case.ID, variant, err)
			}
			if _, err := findFindings(runDir); err != nil {
				return fmt.Errorf("%s/%s: %w", c.Case.ID, variant, err)
			}
		}
	}
	return scoreAndWrite(cases, resultsDir)
}

func expandCommand(template string, values map[string]string) string {
	out := template
	for key, value := range values {
		out = strings.ReplaceAll(out, "{"+key+"}", shellQuote(value))
	}
	return out
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func scoreAndWrite(cases []loadedCase, resultsDir string) error {
	report, err := buildScore(cases, resultsDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(resultsDir, "score.json")
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return err
	}
	markdownPath := filepath.Join(resultsDir, "score.md")
	if err := os.WriteFile(markdownPath, []byte(renderMarkdown(report)), 0o644); err != nil {
		return err
	}
	printScore(report, path)
	return nil
}

func renderMarkdown(report scoreReport) string {
	var b strings.Builder
	b.WriteString("# TEECheck Benchmark Score\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", report.GeneratedAt)
	b.WriteString("| Case | Vulnerable | Fixed | Pair |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, c := range report.Cases {
		pair := "fail"
		if c.PairedPass {
			pair = "pass"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.CaseID, c.Vulnerable.Classification, c.Fixed.Classification, pair)
	}
	b.WriteString("\n## Metrics\n\n")
	fmt.Fprintf(&b, "- TP: %d\n- FP: %d\n- FN: %d\n- TN: %d\n", report.Totals.TP, report.Totals.FP, report.Totals.FN, report.Totals.TN)
	fmt.Fprintf(&b, "- Precision: %.4f\n- Recall: %.4f\n- F1: %.4f\n- Specificity: %.4f\n", report.Precision, report.Recall, report.F1, report.Specificity)
	fmt.Fprintf(&b, "- Paired pass rate: %d/%d (%.4f)\n", report.PairedPasses, len(report.Cases), report.PairedRate)
	b.WriteString("\n## Matching Details\n\n")
	for _, c := range report.Cases {
		fmt.Fprintf(&b, "### %s\n\n", c.CaseID)
		fmt.Fprintf(&b, "- Vulnerable: %s, findings=%d", c.Vulnerable.Classification, c.Vulnerable.FindingCount)
		if c.Vulnerable.MatchedFinding != "" {
			fmt.Fprintf(&b, ", matched=%s", c.Vulnerable.MatchedFinding)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "- Fixed: %s, findings=%d", c.Fixed.Classification, c.Fixed.FindingCount)
		if c.Fixed.MatchedFinding != "" {
			fmt.Fprintf(&b, ", matched=%s", c.Fixed.MatchedFinding)
		}
		b.WriteString("\n")
		if len(c.Vulnerable.MatchReasons) > 0 {
			fmt.Fprintf(&b, "- Vulnerable match reasons: %s\n", strings.Join(c.Vulnerable.MatchReasons, ", "))
		}
		if len(c.Fixed.MatchReasons) > 0 {
			fmt.Fprintf(&b, "- Fixed match reasons: %s\n", strings.Join(c.Fixed.MatchReasons, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func buildScore(cases []loadedCase, resultsDir string) (scoreReport, error) {
	report := scoreReport{Schema: "teecheck.benchmark.score.v1", GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, c := range cases {
		vuln, err := scoreVariant(c, "vulnerable", filepath.Join(resultsDir, c.Case.ID, "vulnerable"))
		if err != nil {
			return scoreReport{}, err
		}
		fixed, err := scoreVariant(c, "fixed", filepath.Join(resultsDir, c.Case.ID, "fixed"))
		if err != nil {
			return scoreReport{}, err
		}
		cs := caseScore{CaseID: c.Case.ID, Vulnerable: vuln, Fixed: fixed}
		cs.PairedPass = vuln.Classification == "TP" && fixed.Classification == "TN"
		if cs.PairedPass {
			report.PairedPasses++
		}
		addClass(&report.Totals, vuln.Classification)
		addClass(&report.Totals, fixed.Classification)
		report.Cases = append(report.Cases, cs)
	}
	report.Precision = ratio(report.Totals.TP, report.Totals.TP+report.Totals.FP)
	report.Recall = ratio(report.Totals.TP, report.Totals.TP+report.Totals.FN)
	report.Specificity = ratio(report.Totals.TN, report.Totals.TN+report.Totals.FP)
	if report.Precision+report.Recall > 0 {
		report.F1 = 2 * report.Precision * report.Recall / (report.Precision + report.Recall)
	}
	report.PairedRate = ratio(report.PairedPasses, len(report.Cases))
	return report, nil
}

func scoreVariant(c loadedCase, variant, resultDir string) (variantScore, error) {
	path, err := findFindings(resultDir)
	if err != nil {
		return variantScore{}, fmt.Errorf("%s/%s: %w", c.Case.ID, variant, err)
	}
	var findings teecheckFindings
	if err := readJSON(path, &findings); err != nil {
		return variantScore{}, err
	}
	expected := "clean"
	if variant == "vulnerable" {
		expected = "vulnerable"
	}
	result := variantScore{Variant: variant, Expected: expected, Observed: "clean", FindingsPath: path, FindingCount: len(findings.Findings)}
	for _, finding := range findings.Findings {
		matched, reasons := matchFinding(c.Oracle, finding)
		if matched {
			result.Observed = "vulnerable"
			result.MatchedFinding = finding.FindingID
			result.MatchReasons = reasons
			break
		}
	}
	if variant == "vulnerable" {
		if result.Observed == "vulnerable" {
			result.Classification = "TP"
		} else {
			result.Classification = "FN"
		}
	} else if result.Observed == "vulnerable" {
		result.Classification = "FP"
	} else {
		result.Classification = "TN"
	}
	return result, nil
}

func matchFinding(oracle oracleSpec, finding teecheckFinding) (bool, []string) {
	status := strings.ToLower(strings.TrimSpace(finding.Status))
	if status == "no_issue_observed" || status == "dismissed" || status == "false_positive" {
		return false, nil
	}
	fileMatch := false
	for _, file := range finding.Files {
		clean := filepath.ToSlash(filepath.Clean(file))
		if clean == oracle.PrimaryFile || strings.HasSuffix(clean, "/"+oracle.PrimaryFile) {
			fileMatch = true
			break
		}
	}
	if !fileMatch {
		return false, nil
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Summary}, finding.Evidence...), "\n"))
	var reasons []string
	if strings.Contains(text, strings.ToLower(oracle.PrimaryFunction)) {
		reasons = append(reasons, "primary_function:"+oracle.PrimaryFunction)
	}
	for _, term := range oracle.MatchTerms {
		if strings.Contains(text, strings.ToLower(term)) {
			reasons = append(reasons, "term:"+term)
		}
	}
	return len(reasons) > 0, append([]string{"primary_file:" + oracle.PrimaryFile}, reasons...)
}

func findFindings(root string) (string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "findings.json" {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return "", errors.New("no findings.json produced")
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple findings.json files: %v", matches)
	}
	return matches[0], nil
}

func addClass(t *scoreTotals, class string) {
	switch class {
	case "TP":
		t.TP++
	case "FP":
		t.FP++
	case "FN":
		t.FN++
	case "TN":
		t.TN++
	}
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return math.Round((float64(numerator)/float64(denominator))*10000) / 10000
}

func printScore(report scoreReport, path string) {
	for _, c := range report.Cases {
		fmt.Printf("CASE %s vulnerable=%s fixed=%s paired=%t\n", c.CaseID, c.Vulnerable.Classification, c.Fixed.Classification, c.PairedPass)
	}
	fmt.Printf("TOTAL TP=%d FP=%d FN=%d TN=%d precision=%.4f recall=%.4f F1=%.4f specificity=%.4f paired=%d/%d\n", report.Totals.TP, report.Totals.FP, report.Totals.FN, report.Totals.TN, report.Precision, report.Recall, report.F1, report.Specificity, report.PairedPasses, len(report.Cases))
	fmt.Printf("REPORT %s\n", path)
}
