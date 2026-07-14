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
	if report.Totals != (scoreTotals{TP: len(cases), TN: len(cases)}) {
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

func TestMatchFindingRejectsSingleGenericTerm(t *testing.T) {
	// Find a case whose match_terms contain a term distinct from the
	// primary function, so we can exercise the "one generic term" path.
	var c loadedCase
	var generic string
	for _, cand := range loadRepositoryCases(t) {
		for _, term := range cand.Oracle.MatchTerms {
			if term != cand.Oracle.PrimaryFunction {
				c, generic = cand, term
				break
			}
		}
		if generic != "" {
			break
		}
	}
	if generic == "" {
		t.Skip("no case with a non-function match term")
	}
	matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Files:   []string{c.Oracle.PrimaryFile},
		Summary: "the " + generic + " field is fine here",
	})
	if matched {
		t.Fatalf("a single generic term %q on the right file must not match", generic)
	}
}

func TestMatchFindingAcceptsTwoTerms(t *testing.T) {
	var c loadedCase
	var terms []string
	for _, cand := range loadRepositoryCases(t) {
		var distinct []string
		for _, term := range cand.Oracle.MatchTerms {
			if term != cand.Oracle.PrimaryFunction {
				distinct = append(distinct, term)
			}
		}
		if len(distinct) >= 2 {
			c, terms = cand, distinct
			break
		}
	}
	if len(terms) < 2 {
		t.Skip("no case with two non-function match terms")
	}
	matched, _ := matchFinding(c.Oracle, teecheckFinding{
		Files:   []string{c.Oracle.PrimaryFile},
		Summary: terms[0] + " combined with " + terms[1] + " triggers the issue",
	})
	if !matched {
		t.Fatalf("two corroborating terms %v should match", terms[:2])
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

func TestContainsPathAcceptsDirectoryScanRoot(t *testing.T) {
	if !containsPath([]string{"syscall"}, "syscall/devices/hostsock/hostsock.c") {
		t.Fatal("directory scan root should cover the oracle primary file")
	}
	if containsPath([]string{"syscall/devices/hostsock"}, "syscall/socket.c") {
		t.Fatal("unrelated sibling must not be covered by a directory scan root")
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
		if c.Case.Status == "pending_source" {
			continue
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
