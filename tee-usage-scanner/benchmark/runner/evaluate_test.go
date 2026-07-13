package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildScorePairedResults(t *testing.T) {
	cases := loadRepositoryCases(t)
	results := t.TempDir()
	for _, c := range cases {
		writeFindings(t, results, c.Case.ID, "vulnerable", []teecheckFinding{{
			FindingID: "finding-1",
			Files:     []string{c.Oracle.PrimaryFile},
			Summary:   c.Oracle.PrimaryFunction + " reaches " + c.Oracle.MatchTerms[0],
		}})
		writeFindings(t, results, c.Case.ID, "fixed", nil)
	}
	report, err := buildScore(cases, results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals != (scoreTotals{TP: 3, TN: 3}) {
		t.Fatalf("totals=%+v", report.Totals)
	}
	if report.Precision != 1 || report.Recall != 1 || report.F1 != 1 || report.Specificity != 1 || report.PairedRate != 1 {
		t.Fatalf("metrics=%+v", report)
	}
}

func TestBuildScoreReportsFalseNegativeAndFalsePositive(t *testing.T) {
	cases := loadRepositoryCases(t)[:1]
	c := cases[0]
	results := t.TempDir()
	writeFindings(t, results, c.Case.ID, "vulnerable", nil)
	writeFindings(t, results, c.Case.ID, "fixed", []teecheckFinding{{
		FindingID: "fixed-hit",
		Files:     []string{c.Oracle.PrimaryFile},
		Summary:   c.Oracle.MatchTerms[0],
	}})
	report, err := buildScore(cases, results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals != (scoreTotals{FP: 1, FN: 1}) {
		t.Fatalf("totals=%+v", report.Totals)
	}
	if report.Cases[0].PairedPass {
		t.Fatal("pair unexpectedly passed")
	}
}

func TestMatchFindingRequiresSemanticEvidence(t *testing.T) {
	c := loadRepositoryCases(t)[0]
	matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Files:   []string{c.Oracle.PrimaryFile},
		Summary: "unrelated issue in the same file",
	})
	if matched {
		t.Fatal("file-only match must not satisfy oracle")
	}
}

func TestMatchFindingIgnoresExplicitNoIssue(t *testing.T) {
	c := loadRepositoryCases(t)[0]
	matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Status:  "no_issue_observed",
		Files:   []string{c.Oracle.PrimaryFile},
		Summary: c.Oracle.PrimaryFunction + " " + c.Oracle.MatchTerms[0],
	})
	if matched {
		t.Fatal("no_issue_observed must not be scored as a vulnerability")
	}
}

func loadRepositoryCases(t *testing.T) []loadedCase {
	t.Helper()
	root := filepath.Join("..", "cases")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var cases []loadedCase
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, err := loadCase(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}
	return cases
}

func writeFindings(t *testing.T, root, caseID, variant string, findings []teecheckFinding) {
	t.Helper()
	dir := filepath.Join(root, caseID, variant, "07_arbiter")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(teecheckFindings{SchemaVersion: "teecheck.findings.v2", RunID: caseID + "-" + variant, Findings: findings})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
